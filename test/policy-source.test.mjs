// The Worker-side refresh layer. The golden vectors carry fixed timestamps that
// are deliberately in the past, so these tests mint their own bundles with a
// throwaway P-256 key: expiry, agent binding and rules all have to vary here,
// and interop with @seekrit/core is already pinned by policy-vectors.test.mjs.
import assert from "node:assert/strict";

import {
  createPolicySource,
  policySignerThumbprint,
  seekritEgress,
  SeekritError,
  SeekritPolicyError,
} from "../dist/cloudflare-computer.js";

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failures++;
    console.error(`FAIL  ${name}\n      ${err.stack ?? err.message}`);
  }
}

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

/** A publisher, as far as the verifier is concerned. */
async function publisher() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const full = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk = { kty: "EC", crv: "P-256", x: full.x, y: full.y };
  const kid = await policySignerThumbprint(jwk);

  return {
    kid,
    async sign(overrides = {}) {
      const now = Math.floor(Date.now() / 1000);
      const body = JSON.stringify({
        v: 1,
        org: "org_test",
        agent: "agt_test",
        agent_slug: "nova",
        policy_version: 1,
        issued_at: now,
        expires_at: now + 3600,
        rules: [{ host: "api.openai.com", methods: [], paths: [], allow: ["OPENAI_API_KEY"] }],
        ...overrides,
        signer: { kid, jwk },
      });
      const bytes = new TextEncoder().encode(body);
      const sig = new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, bytes),
      );
      return `ap1.${b64url(bytes)}.${b64url(sig)}`;
    },
  };
}

/** Counts API hits and can be made to fail or answer 304. */
function api(envelope) {
  const state = { calls: 0, mode: "ok", envelope, etag: 'W/"v1"' };
  const fetchBundle = async (etag) => {
    state.calls++;
    if (state.mode === "fail") throw new SeekritPolicyError("api is down");
    if (state.mode === "304" && etag === state.etag) return { envelope: null, etag };
    return { envelope: state.envelope, etag: state.etag };
  };
  return { state, fetchBundle };
}

function memoryStore() {
  const state = { gets: 0, puts: 0, value: null, ttl: null };
  return {
    state,
    get: async () => {
      state.gets++;
      return state.value;
    },
    put: async (_key, envelope, ttl) => {
      state.puts++;
      state.value = envelope;
      state.ttl = ttl;
    },
  };
}

await check("no pinned signers is a configuration error", async () => {
  const pub = await publisher();
  assert.throws(
    () => createPolicySource({ signers: [], agent: "agt_test", fetchBundle: async () => ({ envelope: await pub.sign() }) }),
    SeekritError,
  );
});

await check("a verified bundle's rules are served, and reused within the interval", async () => {
  const pub = await publisher();
  const upstream = api(await pub.sign());
  const events = [];
  const source = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    org: "org_test",
    refreshSeconds: 3600,
    fetchBundle: upstream.fetchBundle,
    onPolicy: (e) => events.push(e),
  });

  const first = await source.current();
  assert.equal(first.rules[0].host, "api.openai.com");
  await source.current();
  await source.current();
  assert.equal(upstream.state.calls, 1, "one fetch serves the isolate for the interval");
  assert.deepEqual(
    events.map((e) => e.kind),
    ["loaded"],
  );
  assert.equal(events[0].from, "api");
  assert.equal(events[0].policyVersion, 1);
});

await check("concurrent first requests share one fetch", async () => {
  const pub = await publisher();
  const upstream = api(await pub.sign());
  const source = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    fetchBundle: upstream.fetchBundle,
  });
  await Promise.all([source.current(), source.current(), source.current()]);
  assert.equal(upstream.state.calls, 1);
});

await check("a 304 keeps the bundle already in hand", async () => {
  const pub = await publisher();
  const upstream = api(await pub.sign());
  const events = [];
  const source = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    refreshSeconds: 0, // every call is due
    fetchBundle: upstream.fetchBundle,
    onPolicy: (e) => events.push(e),
  });

  await source.current();
  upstream.state.mode = "304";
  const again = await source.current();
  assert.equal(again.bundle.policy_version, 1);
  assert.equal(upstream.state.calls, 2);
  assert.deepEqual(
    events.map((e) => e.kind),
    ["loaded", "not_modified"],
  );
});

await check("a store answers before the API, and is written after it", async () => {
  const pub = await publisher();
  const upstream = api(await pub.sign());
  const store = memoryStore();
  const options = {
    signers: [pub.kid],
    agent: "agt_test",
    refreshSeconds: 0,
    store,
    fetchBundle: upstream.fetchBundle,
  };

  const cold = createPolicySource(options);
  await cold.current();
  assert.equal(upstream.state.calls, 1, "store was empty, so the API answered");
  assert.equal(store.state.puts, 1);
  assert.ok(store.state.ttl >= 60);

  // A second isolate, same store: no API call at all.
  const warm = createPolicySource(options);
  await warm.current();
  assert.equal(upstream.state.calls, 1);
  assert.equal(store.state.gets, 2, "one get per refresh: the cold miss and the warm hit");
});

await check("a store holding a bundle that no longer checks out falls back to the API", async () => {
  const pub = await publisher();
  const upstream = api(await pub.sign());
  const store = memoryStore();
  store.state.value = await pub.sign({ expires_at: Math.floor(Date.now() / 1000) - 1 });

  const source = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    store,
    fetchBundle: upstream.fetchBundle,
  });
  const loaded = await source.current();
  assert.equal(upstream.state.calls, 1);
  assert.ok(loaded.bundle.expires_at > Math.floor(Date.now() / 1000));
});

await check("an expired bundle is refused, however it arrived", async () => {
  const pub = await publisher();
  const upstream = api(await pub.sign({ expires_at: Math.floor(Date.now() / 1000) - 1 }));
  const events = [];
  const source = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    fetchBundle: upstream.fetchBundle,
    onPolicy: (e) => events.push(e),
  });
  await assert.rejects(() => source.current(), SeekritPolicyError);
  assert.equal(events.at(-1).kind, "unusable");
});

await check("a bundle signed by an unpinned key is refused", async () => {
  const mine = await publisher();
  const theirs = await publisher();
  const upstream = api(await theirs.sign());
  const source = createPolicySource({
    signers: [mine.kid],
    agent: "agt_test",
    fetchBundle: upstream.fetchBundle,
  });
  await assert.rejects(() => source.current(), SeekritPolicyError);
});

await check("a bundle for another agent or org is refused", async () => {
  const pub = await publisher();
  const wrongAgent = createPolicySource({
    signers: [pub.kid],
    agent: "agt_someoneElse",
    fetchBundle: api(await pub.sign()).fetchBundle,
  });
  await assert.rejects(() => wrongAgent.current(), SeekritPolicyError);

  const wrongOrg = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    org: "org_someoneElse",
    fetchBundle: api(await pub.sign()).fetchBundle,
  });
  await assert.rejects(() => wrongOrg.current(), SeekritPolicyError);
});

await check("the slug is accepted where the id is, because that is what people write", async () => {
  const pub = await publisher();
  const source = createPolicySource({
    signers: [pub.kid],
    agent: "nova",
    fetchBundle: api(await pub.sign()).fetchBundle,
  });
  assert.equal((await source.current()).bundle.agent, "agt_test");
});

await check("a bundle exceeding the local ceiling is refused wholesale", async () => {
  const pub = await publisher();
  const source = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    ceiling: { "api.openai.com": [] },
    fetchBundle: api(await pub.sign()).fetchBundle,
  });
  await assert.rejects(() => source.current(), SeekritPolicyError);

  const within = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    ceiling: { "api.openai.com": ["OPENAI_API_KEY", "UNUSED"] },
    fetchBundle: api(await pub.sign()).fetchBundle,
  });
  assert.equal((await within.current()).rules.length, 1);
});

await check("a failed refresh keeps serving a bundle that has not expired", async () => {
  const pub = await publisher();
  const upstream = api(await pub.sign());
  const events = [];
  const source = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    refreshSeconds: 0,
    fetchBundle: upstream.fetchBundle,
    onPolicy: (e) => events.push(e),
  });
  await source.current();
  upstream.state.mode = "fail";
  const still = await source.current();
  assert.equal(still.bundle.policy_version, 1);
  assert.equal(events.at(-1).kind, "refresh_failed");
});

await check("waitUntil moves the refresh off the request path", async () => {
  const pub = await publisher();
  const upstream = api(await pub.sign());
  const background = [];
  const source = createPolicySource({
    signers: [pub.kid],
    agent: "agt_test",
    refreshSeconds: 0,
    waitUntil: (p) => background.push(p),
    fetchBundle: upstream.fetchBundle,
  });

  await source.current(); // first load has to wait; nothing to serve yet
  assert.equal(background.length, 0);
  assert.equal(upstream.state.calls, 1);

  upstream.state.envelope = await pub.sign({ policy_version: 2 });
  const stale = await source.current();
  assert.equal(stale.bundle.policy_version, 1, "served immediately from what was in hand");
  assert.equal(background.length, 1);
  await Promise.all(background);
  assert.equal((await source.current()).bundle.policy_version, 2);
});

// ---------------------------------------------------------------------------
// The gateway on top of it
// ---------------------------------------------------------------------------

function upstreamFetch() {
  const seen = [];
  return {
    seen,
    impl: async (input, init) => {
      seen.push({ url: String(input), auth: new Headers(init?.headers).get("authorization") });
      return new Response("ok");
    },
  };
}

await check("a static allowlist and a policy source are mutually exclusive", async () => {
  const pub = await publisher();
  assert.throws(
    () =>
      seekritEgress({
        allow: { "api.openai.com": ["OPENAI_API_KEY"] },
        policy: { signers: [pub.kid], agent: "agt_test", fetchBundle: async () => ({ envelope: null }) },
      }),
    SeekritError,
  );
});

await check("the gateway enforces the rules a signed bundle carries", async () => {
  const pub = await publisher();
  const sent = upstreamFetch();
  const egress = seekritEgress({
    client: { resolve: async () => ({ OPENAI_API_KEY: "sk-live-abc" }) },
    fetch: sent.impl,
    policy: {
      signers: [pub.kid],
      agent: "agt_test",
      fetchBundle: api(await pub.sign()).fetchBundle,
    },
  });

  const allowed = await egress.fetch(
    new Request("https://api.openai.com/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
  );
  assert.equal(allowed.status, 200);
  assert.equal(sent.seen[0].auth, "Bearer sk-live-abc");

  const denied = await egress.fetch(new Request("https://evil.example/"));
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.get("x-seekrit-refusal"), "no_rule");
  assert.equal(sent.seen.length, 1);
});

await check("no usable policy means nothing is permitted", async () => {
  const pub = await publisher();
  const sent = upstreamFetch();
  const refusals = [];
  const egress = seekritEgress({
    client: { resolve: async () => ({ OPENAI_API_KEY: "sk-live-abc" }) },
    fetch: sent.impl,
    onRefuse: (r) => refusals.push(r),
    policy: {
      signers: [pub.kid],
      agent: "agt_test",
      // Correctly signed, but expired: the strongest form of "do not enforce me".
      fetchBundle: api(await pub.sign({ expires_at: Math.floor(Date.now() / 1000) - 1 }))
        .fetchBundle,
    },
  });

  const res = await egress.fetch(new Request("https://api.openai.com/v1/models"));
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-seekrit-refusal"), "no_policy");
  assert.match(await res.text(), /expired/);
  assert.equal(sent.seen.length, 0);
  assert.equal(refusals[0].reason, "no_policy");
});

if (failures > 0) {
  console.error(`\n${failures} policy source test(s) failed`);
  process.exit(1);
}
console.log("\nall policy source tests passed");
