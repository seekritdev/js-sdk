// The Cloudflare Computer adapter. `@cloudflare/computer` is not a dependency
// here — every shape the adapter touches is declared structurally — so these
// tests stand in for it with what the platform actually hands a gateway: a
// plain `Request` carrying the real target URL, which is what
// `CloudflareContainerBackend.handleFetch` and `globalOutbound` both deliver.
import assert from "node:assert/strict";

import {
  resolveEnv,
  seekritEgress,
  seekritEgressPolicy,
  seekritEnv,
} from "../dist/cloudflare-computer.js";
import { SeekritError } from "../dist/index.js";

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

const KEYS = { OPENAI_API_KEY: "sk-live-abc", GITHUB_TOKEN: "ghp_xyz" };

/** Records everything that made it upstream. */
function upstream(respond = () => new Response("ok", { status: 200 })) {
  const seen = [];
  const impl = async (input, init) => {
    const headers = new Headers(init?.headers);
    let body;
    if (init?.body instanceof ArrayBuffer) body = new Uint8Array(init.body);
    else if (init?.body instanceof Uint8Array) body = init.body;
    seen.push({
      url: String(input),
      method: init?.method,
      redirect: init?.redirect,
      headers,
      auth: headers.get("authorization"),
      body,
      text: body === undefined ? undefined : new TextDecoder().decode(body),
    });
    return respond();
  };
  return { seen, impl };
}

/** A resolve source that counts how often it was asked. */
function source(values = KEYS) {
  const state = { calls: 0 };
  return {
    state,
    resolve: async () => {
      state.calls++;
      return { ...values };
    },
  };
}

const ALLOW_OPENAI = { "api.openai.com": ["OPENAI_API_KEY"] };

function gateway(options = {}) {
  const sent = upstream(options.respond);
  const client = options.client ?? source(options.values);
  const egress = seekritEgress({
    allow: options.allow ?? ALLOW_OPENAI,
    rules: options.rules,
    client,
    fetch: sent.impl,
    ...options.extra,
  });
  return { egress, sent, client };
}

await check("a gateway with no rules is a configuration error, not a silent block", () => {
  assert.throws(() => seekritEgress({ client: source() }), SeekritError);
});

await check("default-deny: an unlisted host is refused and never sent", async () => {
  const { egress, sent, client } = gateway();
  const res = await egress.fetch(new Request("https://evil.example/steal"));
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-seekrit-refusal"), "no_rule");
  assert.match(await res.text(), /no policy rule covers this upstream/);
  assert.equal(sent.seen.length, 0);
  assert.equal(client.state.calls, 0, "a refused operation must not resolve");
});

await check("method and path narrowing refuse with the constraint that refused", async () => {
  const rules = [
    { host: "api.github.com", methods: ["POST"], paths: ["/repos/**"], allow: ["GITHUB_TOKEN"] },
  ];
  const { egress, sent } = gateway({ allow: {}, rules });

  const wrongPath = await egress.fetch(new Request("https://api.github.com/user"));
  assert.equal(wrongPath.status, 403);
  assert.equal(wrongPath.headers.get("x-seekrit-refusal"), "path_not_allowed");

  const wrongMethod = await egress.fetch(new Request("https://api.github.com/repos/a/b"));
  assert.equal(wrongMethod.headers.get("x-seekrit-refusal"), "method_not_allowed");

  assert.equal(sent.seen.length, 0);
});

await check("a permitted request with no placeholder passes through without resolving", async () => {
  const { egress, sent, client } = gateway();
  const res = await egress.fetch(new Request("https://api.openai.com/v1/models"));
  assert.equal(res.status, 200);
  assert.equal(sent.seen.length, 1);
  assert.equal(sent.seen[0].url, "https://api.openai.com/v1/models");
  assert.equal(client.state.calls, 0);
});

await check("a rule with allow: [] permits the host and no secret", async () => {
  const rules = [{ host: "pypi.org", allow: [] }];
  const { egress, sent } = gateway({ allow: {}, rules });

  const plain = await egress.fetch(new Request("https://pypi.org/simple/flask/"));
  assert.equal(plain.status, 200);
  assert.equal(sent.seen.length, 1);

  const withSecret = await egress.fetch(
    new Request("https://pypi.org/simple/", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
  );
  assert.equal(withSecret.status, 403);
  assert.equal(withSecret.headers.get("x-seekrit-refusal"), "denied");
  assert.equal(sent.seen.length, 1, "the denied request must not be sent");
});

await check("a placeholder in a header becomes the credential", async () => {
  const { egress, sent } = gateway();
  const res = await egress.fetch(
    new Request("https://api.openai.com/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
  );
  assert.equal(res.status, 200);
  assert.equal(sent.seen[0].auth, "Bearer sk-live-abc");
});

await check("a placeholder in the query string becomes the credential", async () => {
  const { egress, sent } = gateway();
  await egress.fetch(new Request("https://api.openai.com/v1/models?key={{seekrit:OPENAI_API_KEY}}"));
  assert.equal(sent.seen[0].url, "https://api.openai.com/v1/models?key=sk-live-abc");
});

await check("a placeholder in a JSON body becomes the credential", async () => {
  const { egress, sent } = gateway();
  await egress.fetch(
    new Request("https://api.openai.com/v1/models", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key: "{{seekrit:OPENAI_API_KEY}}" }),
    }),
  );
  assert.equal(sent.seen[0].method, "POST");
  assert.equal(sent.seen[0].text, JSON.stringify({ key: "sk-live-abc" }));
});

await check("a substituted body does not carry the sandbox's content-length", async () => {
  const { egress, sent } = gateway();
  const body = JSON.stringify({ key: "{{seekrit:OPENAI_API_KEY}}" });
  await egress.fetch(
    new Request("https://api.openai.com/v1/models", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(body.length) },
      body,
    }),
  );
  assert.equal(sent.seen[0].headers.get("content-length"), null);
  assert.equal(sent.seen[0].headers.get("content-type"), "application/json");
  assert.notEqual(sent.seen[0].text.length, body.length);
});

await check("a secret the host may not receive is refused, and never sent", async () => {
  const { egress, sent } = gateway();
  const res = await egress.fetch(
    new Request("https://api.openai.com/v1/models", {
      headers: { authorization: "Bearer {{seekrit:GITHUB_TOKEN}}" },
    }),
  );
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-seekrit-refusal"), "denied");
  assert.equal(res.headers.get("x-seekrit-secret"), "GITHUB_TOKEN");
  assert.match(await res.text(), /is not allowed toward this upstream/);
  assert.equal(sent.seen.length, 0);
});

await check("a permitted name that did not resolve is refused, not forwarded", async () => {
  const { egress, sent } = gateway({ values: {} });
  const res = await egress.fetch(
    new Request("https://api.openai.com/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
  );
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-seekrit-refusal"), "unresolved");
  assert.equal(sent.seen.length, 0);
});

await check("a placeholder in the path survives the URL parser's encoding", async () => {
  const { egress, sent } = gateway();
  // `new Request()` normalises this to `/v1/models/%7B%7Bseekrit:OPENAI_API_KEY%7D%7D`.
  await egress.fetch(new Request("https://api.openai.com/v1/models/{{seekrit:OPENAI_API_KEY}}"));
  assert.equal(sent.seen[0].url, "https://api.openai.com/v1/models/sk-live-abc");
});

await check("substitution cannot move a request to another origin", async () => {
  const { egress, sent } = gateway({
    allow: { "api.openai.com": ["PATH"] },
    values: { PATH: "evil.example/x" },
  });
  const res = await egress.fetch(new Request("https://api.openai.com/{{seekrit:PATH}}"));
  // The value lands in the path, not the authority: a placeholder can only sit
  // after the authority, so the request still goes to the host that was checked.
  assert.equal(res.status, 200);
  assert.equal(new URL(sent.seen[0].url).host, "api.openai.com");
});

await check("redirects are never followed by the gateway", async () => {
  const { egress, sent } = gateway();
  await egress.fetch(new Request("https://api.openai.com/v1/models"));
  assert.equal(sent.seen[0].redirect, "manual");
});

await check("a body over the cap is refused rather than forwarded unscanned", async () => {
  const { egress, sent } = gateway({ extra: { maxBodyBytes: 16 } });
  const res = await egress.fetch(
    new Request("https://api.openai.com/v1/files", { method: "POST", body: "x".repeat(64) }),
  );
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("x-seekrit-refusal"), "body_too_large");
  assert.match(await res.text(), /limit 16 bytes/);
  assert.equal(sent.seen.length, 0);
});

await check("body: false streams every body through untouched", async () => {
  const { egress, sent } = gateway({ extra: { body: false, maxBodyBytes: 4 } });
  const res = await egress.fetch(
    new Request("https://api.openai.com/v1/files", { method: "POST", body: "x".repeat(64) }),
  );
  assert.equal(res.status, 200);
  assert.equal(sent.seen.length, 1);
});

await check("a binary body is forwarded byte-for-byte", async () => {
  const { egress, sent } = gateway();
  const bytes = new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0x41]); // not valid UTF-8
  await egress.fetch(
    new Request("https://api.openai.com/v1/files", { method: "POST", body: bytes }),
  );
  assert.deepEqual(new Uint8Array(sent.seen[0].body), bytes);
});

await check("one resolve serves many requests, until the TTL says otherwise", async () => {
  const client = source();
  const { egress } = gateway({ client });
  const authed = () =>
    new Request("https://api.openai.com/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    });
  await egress.fetch(authed());
  await egress.fetch(authed());
  assert.equal(client.state.calls, 1);

  const fresh = source();
  const nocache = gateway({ client: fresh, extra: { ttlSeconds: 0 } });
  await nocache.egress.fetch(authed());
  await nocache.egress.fetch(authed());
  assert.equal(fresh.state.calls, 2);
});

await check("onInject and onRefuse report names and constraints, never values", async () => {
  const injected = [];
  const refused = [];
  const { egress } = gateway({ extra: { onInject: (e) => injected.push(e), onRefuse: (r) => refused.push(r) } });

  await egress.fetch(
    new Request("https://api.openai.com/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
  );
  assert.deepEqual(injected, [
    { host: "api.openai.com", method: "GET", path: "/v1/models", names: ["OPENAI_API_KEY"] },
  ]);

  await egress.fetch(new Request("https://evil.example/"));
  assert.equal(refused.length, 1);
  assert.equal(refused[0].reason, "operation");
  assert.equal(refused[0].decision, "no_rule");
  assert.equal(refused[0].host, "evil.example");
  assert.equal(
    JSON.stringify([...injected, ...refused]).includes(KEYS.OPENAI_API_KEY),
    false,
    "no callback may carry a value",
  );
});

await check("seekritEnv hands the sandbox markers, not credentials", () => {
  assert.deepEqual(seekritEnv(["OPENAI_API_KEY"]), {
    OPENAI_API_KEY: "{{seekrit:OPENAI_API_KEY}}",
  });
  assert.deepEqual(seekritEnv({ OPENAI_KEY: "OPENAI_API_KEY" }), {
    OPENAI_KEY: "{{seekrit:OPENAI_API_KEY}}",
  });
  assert.throws(() => seekritEnv(["not a name"]), SeekritError);
});

await check("resolveEnv takes named secrets only, and fails closed on a missing one", async () => {
  assert.deepEqual(await resolveEnv(source(), ["GITHUB_TOKEN"]), { GITHUB_TOKEN: "ghp_xyz" });
  assert.deepEqual(await resolveEnv(source(), { GH: "GITHUB_TOKEN" }), { GH: "ghp_xyz" });
  await assert.rejects(() => resolveEnv(source(), ["NOPE"]), SeekritError);
});

await check("seekritEgressPolicy keeps the gateway's own type and omits an absent revision", () => {
  const g = { fetch: async () => new Response("") };
  assert.deepEqual(Object.keys(seekritEgressPolicy(g)), ["mode", "gateway"]);
  const pinned = seekritEgressPolicy(g, "v1");
  assert.equal(pinned.mode, "http-gateway");
  assert.equal(pinned.revision, "v1");
  assert.equal(pinned.gateway, g);
});

if (failures > 0) {
  console.error(`\n${failures} cloudflare-computer test(s) failed`);
  process.exit(1);
}
console.log("\nall cloudflare-computer tests passed");
