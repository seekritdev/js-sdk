// Functional tests for `@seekrit/sdk/route` — the route handler that holds the
// key while the browser holds a placeholder.
//
// Plain script (no test-runner) so it runs identically on every runtime:
//   node test/route.test.mjs
import assert from "node:assert/strict";

import { SeekritError } from "../dist/index.js";
import { seekritRoute } from "../dist/route.js";

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

function fakeClient(values) {
  return {
    calls: 0,
    resolve() {
      this.calls++;
      return Promise.resolve({ ...values });
    },
  };
}

/** An upstream that records what it was handed instead of sending it. */
function upstreamRecorder(respond) {
  const seen = { count: 0 };
  const impl = async (input, init) => {
    seen.count++;
    seen.url = String(input);
    seen.method = (init?.method ?? "GET").toUpperCase();
    seen.headers = Object.fromEntries(new Headers(init?.headers ?? {}).entries());
    seen.body = init?.body ? new TextDecoder().decode(init.body) : null;
    return respond ? respond() : new Response(JSON.stringify({ ok: true }), { status: 200 });
  };
  return { seen, impl };
}

const KEYS = { OPENAI_API_KEY: "sk-live-abc", STRIPE_SECRET_KEY: "sk_test_stripe" };

/** The handler under test, wired to a stub upstream and a stub resolve. */
function route(overrides = {}) {
  const { seen, impl } = upstreamRecorder(overrides.respond);
  const handlers = seekritRoute({
    upstream: "https://api.openai.com",
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    authorize: () => true,
    client: fakeClient(KEYS),
    fetch: impl,
    ...overrides,
  });
  return { handlers, seen };
}

/** Next.js hands a catch-all route its tail as `params`, as a promise. */
function params(...segments) {
  return { params: Promise.resolve({ path: segments }) };
}

await check("substitutes a placeholder header and rewrites onto the upstream", async () => {
  const injected = [];
  const { handlers, seen } = route({ onInject: (e) => injected.push(e) });
  const response = await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        authorization: "Bearer {{seekrit:OPENAI_API_KEY}}",
        "content-type": "application/json",
      },
      body: JSON.stringify({ model: "gpt-5.6-sol" }),
    }),
    params("v1", "chat", "completions"),
  );

  assert.equal(response.status, 200);
  assert.equal(seen.url, "https://api.openai.com/v1/chat/completions");
  assert.equal(seen.method, "POST");
  assert.equal(seen.headers.authorization, `Bearer ${KEYS.OPENAI_API_KEY}`);
  assert.equal(seen.headers["content-type"], "application/json");
  assert.deepEqual(injected, [
    {
      host: "api.openai.com",
      method: "POST",
      path: "/v1/chat/completions",
      names: ["OPENAI_API_KEY"],
    },
  ]);
});

await check("a placeholder in the body is substituted too", async () => {
  const { handlers, seen } = route();
  await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key: "{{seekrit:OPENAI_API_KEY}}" }),
    }),
    params("v1", "responses"),
  );
  assert.equal(JSON.parse(seen.body).key, KEYS.OPENAI_API_KEY);
});

await check("the query string is carried onto the upstream", async () => {
  const { handlers, seen } = route();
  await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/models?limit=2", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "models"),
  );
  assert.equal(seen.url, "https://api.openai.com/v1/models?limit=2");
});

await check("basePath derives the tail when the framework passes no params", async () => {
  const { handlers, seen } = route({ basePath: "/api/openai" });
  await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
  );
  assert.equal(seen.url, "https://api.openai.com/v1/models");
});

// --- the boundary -----------------------------------------------------------

await check("authorize is required — no handler without one", async () => {
  assert.throws(
    () =>
      seekritRoute({
        upstream: "https://api.openai.com",
        allow: { "api.openai.com": ["OPENAI_API_KEY"] },
      }),
    (error) => {
      assert.ok(error instanceof SeekritError);
      assert.match(error.message, /open credential proxy/);
      return true;
    },
  );
});

await check("an allowlist is required", async () => {
  assert.throws(
    () => seekritRoute({ upstream: "https://api.openai.com", authorize: () => true }),
    /needs an allowlist/,
  );
});

await check("a rejected caller gets 401 and the upstream is never called", async () => {
  const { handlers, seen } = route({ authorize: () => false });
  const response = await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "chat"),
  );
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("x-seekrit-refusal"), "unauthorized");
  assert.equal(seen.count, 0);
  assert.ok(!(await response.text()).includes(KEYS.OPENAI_API_KEY));
});

await check("the operation is gated even with no placeholder to substitute", async () => {
  // The whole point of the extra check: an authorized caller must not be able to
  // drive an out-of-policy path just by leaving the placeholder out.
  const { handlers, seen } = route({
    rules: [{ host: "api.openai.com", methods: ["POST"], paths: ["/v1/chat/**"], allow: ["OPENAI_API_KEY"] }],
    allow: undefined,
  });
  const response = await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/organizations"),
    params("v1", "organizations"),
  );
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("x-seekrit-refusal"), "path_not_allowed");
  assert.equal(seen.count, 0);
});

await check("a method outside the rule is refused", async () => {
  const { handlers, seen } = route({
    rules: [{ host: "api.openai.com", methods: ["POST"], paths: [], allow: ["OPENAI_API_KEY"] }],
    allow: undefined,
  });
  const response = await handlers.DELETE(
    new Request("https://app.example.com/api/openai/v1/files/1", { method: "DELETE" }),
    params("v1", "files", "1"),
  );
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("x-seekrit-refusal"), "method_not_allowed");
  assert.equal(seen.count, 0);
});

await check("a placeholder the allowlist does not permit is refused, names only", async () => {
  const { handlers, seen } = route();
  const response = await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: { authorization: "Bearer {{seekrit:STRIPE_SECRET_KEY}}" },
    }),
    params("v1", "chat"),
  );
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("x-seekrit-refusal"), "denied");
  assert.equal(response.headers.get("x-seekrit-secret"), "STRIPE_SECRET_KEY");
  const body = await response.text();
  assert.ok(body.includes("{{seekrit:STRIPE_SECRET_KEY}}"));
  assert.ok(!body.includes(KEYS.STRIPE_SECRET_KEY), "a refusal must not carry the value");
  assert.equal(seen.count, 0);
});

await check("a permitted name that did not resolve is refused", async () => {
  const { handlers, seen } = route({ client: fakeClient({}) });
  const response = await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "chat"),
  );
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("x-seekrit-refusal"), "unresolved");
  assert.equal(seen.count, 0);
});

await check("an upstream function returning nothing is a 404", async () => {
  const { handlers, seen } = route({ upstream: () => undefined });
  const response = await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/models"),
    params("v1", "models"),
  );
  assert.equal(response.status, 404);
  assert.equal(seen.count, 0);
});

await check("an upstream function's URL is still subject to the allowlist", async () => {
  const { handlers, seen } = route({ upstream: () => "https://evil.example.com/v1/chat" });
  const response = await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/chat"),
    params("v1", "chat"),
  );
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("x-seekrit-refusal"), "no_rule");
  assert.equal(seen.count, 0);
});

// --- header hygiene ---------------------------------------------------------

await check("the app's own cookie and session never reach the upstream", async () => {
  const { handlers, seen } = route();
  await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: {
        cookie: "session=super-secret-session",
        origin: "https://app.example.com",
        referer: "https://app.example.com/chat",
        "x-forwarded-for": "203.0.113.7",
        "accept-encoding": "gzip, br",
        "x-request-id": "keep-me",
        "content-type": "application/json",
      },
      body: JSON.stringify({ key: "{{seekrit:OPENAI_API_KEY}}" }),
    }),
    params("v1", "chat"),
  );
  for (const dropped of ["cookie", "origin", "referer", "x-forwarded-for", "accept-encoding", "host"]) {
    assert.equal(seen.headers[dropped], undefined, dropped);
  }
  assert.equal(seen.headers["x-request-id"], "keep-me");
});

await check("a real authorization header is dropped; a placeholder one is not", async () => {
  const bare = route();
  await bare.handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: { authorization: "Bearer someone-elses-token", "content-type": "application/json" },
      body: JSON.stringify({ hello: "world" }),
    }),
    params("v1", "chat"),
  );
  assert.equal(bare.seen.headers.authorization, undefined);

  const held = route();
  await held.handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "chat"),
  );
  assert.equal(held.seen.headers.authorization, `Bearer ${KEYS.OPENAI_API_KEY}`);
});

await check("the headers hook can rewrite what goes upstream", async () => {
  const { handlers, seen } = route({
    headers: (headers) => {
      headers.set("openai-beta", "assistants=v2");
      return headers;
    },
  });
  await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "models"),
  );
  assert.equal(seen.headers["openai-beta"], "assistants=v2");
});

await check("an upstream Set-Cookie is not relayed onto our origin", async () => {
  const { handlers } = route({
    respond: () =>
      new Response("hi", {
        status: 200,
        headers: {
          "set-cookie": "upstream=1; Path=/",
          "content-encoding": "gzip",
          "x-request-id": "abc",
        },
      }),
  });
  const response = await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "models"),
  );
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(response.headers.get("content-encoding"), null);
  assert.equal(response.headers.get("x-request-id"), "abc");
  assert.equal(await response.text(), "hi");
});

await check("an upstream error status is relayed as-is", async () => {
  const { handlers } = route({
    respond: () => new Response("rate limited", { status: 429 }),
  });
  const response = await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "models"),
  );
  assert.equal(response.status, 429);
});

// --- body handling ----------------------------------------------------------

await check("a body over the cap is refused before the upstream is called", async () => {
  const { handlers, seen } = route({ maxBodyBytes: 16 });
  const response = await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "x".repeat(64),
    }),
    params("v1", "chat"),
  );
  assert.equal(response.status, 413);
  assert.equal(seen.count, 0);
});

await check("a binary body with no placeholder passes through byte-for-byte", async () => {
  const bytes = new Uint8Array([0xff, 0x00, 0xfe, 0x41, 0x80]);
  const { handlers, seen } = route({
    rules: [{ host: "api.openai.com", methods: [], paths: [], allow: ["OPENAI_API_KEY"] }],
    allow: undefined,
    fetch: async (_input, init) => {
      seen.count++;
      seen.raw = new Uint8Array(init.body);
      return new Response("ok");
    },
  });
  await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/audio", {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: bytes,
    }),
    params("v1", "audio"),
  );
  assert.deepEqual(seen.raw, bytes);
});

await check("a GET carries no body upstream", async () => {
  const { handlers, seen } = route();
  await handlers.GET(
    new Request("https://app.example.com/api/openai/v1/models", {
      headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "models"),
  );
  assert.equal(seen.body, null);
});

// --- scoping and caching ----------------------------------------------------

await check("one resolve is shared across requests in the same scope", async () => {
  const client = fakeClient(KEYS);
  const { handlers } = route({ client });
  for (let i = 0; i < 3; i++) {
    await handlers.GET(
      new Request("https://app.example.com/api/openai/v1/models", {
        headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
      }),
      params("v1", "models"),
    );
  }
  assert.equal(client.calls, 1);
});

await check("scope narrows the allowlist per request", async () => {
  const { handlers, seen } = route({
    allow: { "api.openai.com": ["OPENAI_API_KEY", "STRIPE_SECRET_KEY"] },
    scope: (request) =>
      request.headers.get("x-tool") === "chat" ? { allow: ["OPENAI_API_KEY"] } : undefined,
  });
  const denied = await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: { "x-tool": "chat", authorization: "Bearer {{seekrit:STRIPE_SECRET_KEY}}" },
    }),
    params("v1", "chat"),
  );
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.get("x-seekrit-secret"), "STRIPE_SECRET_KEY");
  assert.equal(seen.count, 0);

  const allowed = await handlers.POST(
    new Request("https://app.example.com/api/openai/v1/chat", {
      method: "POST",
      headers: { "x-tool": "chat", authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
    }),
    params("v1", "chat"),
  );
  assert.equal(allowed.status, 200);
});

await check("the browser build of the entrypoint refuses to load", async () => {
  await assert.rejects(() => import("../dist/route.browser.js"), (error) => {
    assert.match(error.message, /server-only/);
    return true;
  });
});

if (failures > 0) {
  console.error(`\n${failures} route test(s) failed`);
  process.exit(1);
}
console.log("\nall route tests passed");
