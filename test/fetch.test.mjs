// Functional tests for `seekritFetch` — the credential shim, exercised through
// the same surface a provider SDK uses: `fetch(url, init)`.
//
// Plain script (no test-runner) so it runs identically on every runtime:
//   node test/fetch.test.mjs
import assert from "node:assert/strict";

import { SeekritError } from "../dist/index.js";
import { evaluate, matchPath, SeekritSubstitutionError, seekritFetch } from "../dist/fetch.js";

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

/** A stub client: counts resolves so caching is observable. */
function fakeClient(values) {
  return { calls: 0, resolve() { this.calls++; return Promise.resolve({ ...values }); } };
}

/** An upstream that records what it was handed instead of sending it. */
function recorder() {
  const seen = {};
  const impl = async (input, init) => {
    const isRequest = typeof input === "object" && input !== null && "url" in input;
    seen.url = isRequest ? input.url : String(input);
    seen.method = (init?.method ?? (isRequest ? input.method : "GET")).toUpperCase();
    const headers = new Headers(init?.headers ?? (isRequest ? input.headers : undefined));
    seen.headers = Object.fromEntries(headers.entries());
    seen.body = init?.body ?? null;
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };
  return { seen, impl };
}

const KEYS = { OPENAI_API_KEY: "sk-live-abc", STRIPE_SECRET_KEY: "sk_test_stripe" };

/**
 * The default refusal: a 403 shaped like the proxy's, never sent upstream.
 * Provider SDKs wrap anything their `fetch` throws into an opaque connection
 * error *and retry it*, so this is what makes a denial legible.
 */
async function assertRefused(promise, { code, name }) {
  const res = await promise;
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-seekrit-refusal"), code);
  assert.equal(res.headers.get("x-seekrit-secret"), name);
  const body = await res.text();
  assert.ok(body.includes(`{{seekrit:${name}}}`), body);
  assert.ok(!body.includes(KEYS[name] ?? "\u0000"), "a refusal must not carry the value");
}

await check("substitutes a header and reports the injection", async () => {
  const { seen, impl } = recorder();
  const injected = [];
  const client = fakeClient(KEYS);
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client,
    fetch: impl,
    onInject: (e) => injected.push(e),
  });
  const res = await f("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    body: '{"model":"x"}',
  });
  assert.equal(res.status, 200);
  assert.equal(seen.headers.authorization, "Bearer sk-live-abc");
  assert.deepEqual(injected, [
    {
      host: "api.openai.com",
      method: "POST",
      path: "/v1/chat/completions",
      names: ["OPENAI_API_KEY"],
    },
  ]);
});

await check("a request with no placeholder passes through without resolving", async () => {
  const { seen, impl } = recorder();
  const client = fakeClient(KEYS);
  const f = seekritFetch({ allow: { "api.openai.com": ["OPENAI_API_KEY"] }, client, fetch: impl });
  await f("https://api.openai.com/v1/models", { headers: { authorization: "Bearer plain" } });
  assert.equal(seen.headers.authorization, "Bearer plain");
  assert.equal(client.calls, 0, "passthrough must not resolve");
});

await check("a name outside this host's allowlist is refused with a 403", async () => {
  const { seen, impl } = recorder();
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
  });
  await assertRefused(
    f("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer {{seekrit:STRIPE_SECRET_KEY}}" },
    }),
    { code: "denied", name: "STRIPE_SECRET_KEY" },
  );
  assert.equal(seen.url, undefined, "the request must never reach the upstream");
});

await check("refusal: 'throw' raises the typed error instead", async () => {
  const { impl } = recorder();
  const refused = [];
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
    refusal: "throw",
    onRefuse: (err) => refused.push(err),
  });
  await assert.rejects(
    () =>
      f("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { authorization: "Bearer {{seekrit:STRIPE_SECRET_KEY}}" },
      }),
    (err) => {
      assert.ok(err instanceof SeekritSubstitutionError);
      assert.equal(err.code, "denied");
      assert.equal(err.secretName, "STRIPE_SECRET_KEY");
      assert.ok(!err.message.includes("sk_test_stripe"), "error must not carry the value");
      return true;
    },
  );
  assert.equal(refused.length, 1, "onRefuse fires in both modes");
  assert.equal(refused[0].secretName, "STRIPE_SECRET_KEY");
});

await check("the same name toward an unlisted host is denied", async () => {
  const { impl } = recorder();
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
  });
  await assertRefused(
    f("https://evil.example.com/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    { code: "denied", name: "OPENAI_API_KEY" },
  );
});

await check("an allowed name that did not resolve is refused, not forwarded", async () => {
  const { impl } = recorder();
  const f = seekritFetch({
    allow: { "api.openai.com": ["ABSENT_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
  });
  await assertRefused(
    f("https://api.openai.com/v1/x", { headers: { "x-k": "{{seekrit:ABSENT_KEY}}" } }),
    { code: "unresolved", name: "ABSENT_KEY" },
  );
});

await check("substitutes the body and the query string", async () => {
  const { seen, impl } = recorder();
  const f = seekritFetch({
    allow: { "hooks.slack.com": ["OPENAI_API_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
  });
  await f("https://hooks.slack.com/services/x?k={{seekrit:OPENAI_API_KEY}}", {
    method: "POST",
    body: '{"k":"{{seekrit:OPENAI_API_KEY}}"}',
  });
  assert.equal(seen.url, "https://hooks.slack.com/services/x?k=sk-live-abc");
  assert.equal(seen.body, '{"k":"sk-live-abc"}');
});

await check("body scanning can be turned off", async () => {
  const { seen, impl } = recorder();
  const f = seekritFetch({
    allow: { "hooks.slack.com": ["OPENAI_API_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
    body: false,
  });
  await f("https://hooks.slack.com/services/x", {
    method: "POST",
    headers: { "x-k": "{{seekrit:OPENAI_API_KEY}}" },
    body: '{"k":"{{seekrit:OPENAI_API_KEY}}"}',
  });
  assert.equal(seen.headers["x-k"], "sk-live-abc");
  assert.equal(seen.body, '{"k":"{{seekrit:OPENAI_API_KEY}}"}', "body left alone");
});

await check("method and path constraints are enforced", async () => {
  const { seen, impl } = recorder();
  const rules = [
    {
      host: "api.openai.com",
      methods: ["POST"],
      paths: ["/v1/chat/completions"],
      allow: ["OPENAI_API_KEY"],
    },
  ];
  const f = seekritFetch({ rules, client: fakeClient(KEYS), fetch: impl });
  const headers = { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" };
  await f("https://api.openai.com/v1/chat/completions", { method: "POST", headers });
  assert.equal(seen.headers.authorization, "Bearer sk-live-abc");
  await assertRefused(f("https://api.openai.com/v1/chat/completions", { method: "GET", headers }), {
    code: "denied",
    name: "OPENAI_API_KEY",
  });
  await assertRefused(f("https://api.openai.com/v1/embeddings", { method: "POST", headers }), {
    code: "denied",
    name: "OPENAI_API_KEY",
  });
});

await check("a scope narrows the allowlist but cannot widen it", async () => {
  const { seen, impl } = recorder();
  let scope = { allow: ["OPENAI_API_KEY"] };
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY", "STRIPE_SECRET_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
    scope: () => scope,
  });
  await f("https://api.openai.com/v1/x", {
    headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
  });
  assert.equal(seen.headers.authorization, "Bearer sk-live-abc");
  await assertRefused(
    f("https://api.openai.com/v1/x", { headers: { "x-s": "{{seekrit:STRIPE_SECRET_KEY}}" } }),
    { code: "denied", name: "STRIPE_SECRET_KEY" },
  );
  // A scope naming something the static rules never permitted stays denied.
  scope = { allow: ["SOMETHING_ELSE"] };
  await assertRefused(
    f("https://api.openai.com/v1/x", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    { code: "denied", name: "OPENAI_API_KEY" },
  );
});

await check("resolves once per scope within the TTL, and every time at ttl 0", async () => {
  const { impl } = recorder();
  const cached = fakeClient(KEYS);
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: cached,
    fetch: impl,
    ttlSeconds: 60,
  });
  const init = { headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" } };
  for (let i = 0; i < 3; i++) await f("https://api.openai.com/v1/x", init);
  assert.equal(cached.calls, 1);

  const uncached = fakeClient(KEYS);
  const g = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: uncached,
    fetch: impl,
    ttlSeconds: 0,
  });
  for (let i = 0; i < 3; i++) await g("https://api.openai.com/v1/x", init);
  assert.equal(uncached.calls, 3);
});

await check("a Request object keeps its body when its headers are substituted", async () => {
  // The upstream is handed a fresh Request built from the original, so this also
  // asserts the body survives that reconstruction rather than arriving empty.
  const seen = {};
  const impl = async (input) => {
    seen.headers = Object.fromEntries(input.headers.entries());
    seen.body = await input.text();
    return new Response("{}", { status: 200 });
  };
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
  });
  await f(
    new Request("https://api.openai.com/v1/x", {
      method: "POST",
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
      body: '{"model":"x"}',
    }),
  );
  assert.equal(seen.headers.authorization, "Bearer sk-live-abc");
  assert.equal(seen.body, '{"model":"x"}');
});

await check("a placeholder in a Request URL is refused rather than sent", async () => {
  const { impl } = recorder();
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: fakeClient(KEYS),
    fetch: impl,
  });
  await assert.rejects(
    () => f(new Request("https://api.openai.com/v1/x?k={{seekrit:OPENAI_API_KEY}}")),
    SeekritError,
  );
});

await check("an empty allowlist is a configuration error", () => {
  assert.throws(() => seekritFetch({ client: fakeClient(KEYS) }), SeekritError);
});

await check("a failed resolve is not cached", async () => {
  const { impl } = recorder();
  let attempts = 0;
  const flaky = {
    resolve() {
      attempts++;
      return attempts === 1 ? Promise.reject(new Error("boom")) : Promise.resolve({ ...KEYS });
    },
  };
  const f = seekritFetch({
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: flaky,
    fetch: impl,
    ttlSeconds: 60,
  });
  const init = { headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" } };
  await assert.rejects(() => f("https://api.openai.com/v1/x", init));
  await f("https://api.openai.com/v1/x", init); // retried, not a cached rejection
  assert.equal(attempts, 2);
});

// ---------------------------------------------------------------------------
// Allowlist parity with the proxy.
//
// These rules and verdicts are copied verbatim from
// `apps/proxy/testdata/policy-vectors.json` — the fixture generated by the real
// `@seekrit/core` evaluator and asserted by `crates/seekrit-core`. Keeping them
// here means a glob or precedence change in one implementation shows up as a
// failure in the others.
// ---------------------------------------------------------------------------

const RULES = [
  {
    host: "api.openai.com",
    methods: ["POST"],
    paths: ["/v1/chat/completions", "/v1/embeddings"],
    allow: ["OPENAI_API_KEY"],
    label: "chat + embeddings",
  },
  { host: "api.openai.com", methods: ["GET"], paths: ["/v1/models", "/v1/models/*"], allow: [] },
  {
    host: "api.github.com",
    methods: ["GET", "POST"],
    paths: ["/repos/*/issues", "/repos/*/issues/**"],
    allow: ["GITHUB_TOKEN"],
  },
  { host: "hooks.slack.com", methods: [], paths: [], allow: ["SLACK_WEBHOOK_URL"] },
];

const DECISIONS = [
  ["api.openai.com", "POST", "/v1/chat/completions", "OPENAI_API_KEY", "allow", 0],
  ["api.openai.com", "POST", "/v1/chat/completions?stream=true", undefined, "allow", 0],
  ["api.openai.com", "POST", "/v1/chat/completions", "GITHUB_TOKEN", "secret_not_allowed", 0],
  ["api.openai.com", "GET", "/v1/models", undefined, "allow", 1],
  ["api.openai.com", "GET", "/v1/models/gpt-9", "OPENAI_API_KEY", "secret_not_allowed", 1],
  ["api.openai.com", "DELETE", "/v1/models", undefined, "method_not_allowed", 1],
  ["api.openai.com", "POST", "/v1/files", undefined, "path_not_allowed", null],
  ["api.github.com", "POST", "/repos/seekrit/issues", "GITHUB_TOKEN", "allow", 2],
  ["api.github.com", "POST", "/repos/seekrit/issues/12/comments", "GITHUB_TOKEN", "allow", 2],
  ["api.github.com", "POST", "/repos/a/b/issues", undefined, "path_not_allowed", null],
  ["api.github.com", "PATCH", "/repos/seekrit/issues", undefined, "method_not_allowed", 2],
  ["hooks.slack.com", "POST", "/services/T0/B0/xyz", "SLACK_WEBHOOK_URL", "allow", 3],
  ["evil.example.com", "POST", "/", "OPENAI_API_KEY", "no_rule", null],
];

for (const [host, method, path, secret, decision, ruleIndex] of DECISIONS) {
  await check(`policy: ${method} ${host}${path} ${secret ?? "-"} => ${decision}`, () => {
    const verdict = evaluate(RULES, { host, method, path, secret });
    assert.equal(verdict.decision, decision);
    assert.equal(verdict.ruleIndex, ruleIndex);
  });
}

await check("policy: the query string never participates in path matching", () => {
  assert.equal(matchPath("/v1/models", "/v1/models?limit=1"), true);
});

await check("policy: ** covers zero segments, * does not cross one", () => {
  assert.equal(matchPath("/v1/**", "/v1"), true);
  assert.equal(matchPath("/v1/**", "/v1/a/b/c"), true);
  assert.equal(matchPath("/repos/*/issues", "/repos/one/issues"), true);
  assert.equal(matchPath("/repos/*/issues", "/repos/one/two/issues"), false);
});

await check("policy: host matching ignores case", () => {
  const verdict = evaluate(RULES, {
    host: "API.OpenAI.com",
    method: "post",
    path: "/v1/embeddings",
    secret: "OPENAI_API_KEY",
  });
  assert.equal(verdict.decision, "allow");
});

if (failures > 0) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log("\nall fetch tests passed");
