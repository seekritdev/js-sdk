// The Mastra adapter. Mastra itself is not a dependency here — every shape this
// adapter touches is declared structurally — so these tests stand in for it with
// the same objects Mastra passes: a RequestContext with `get`, a Hono-shaped
// middleware context, and a tool execution context.
//
// The integration proper (that Mastra accepts `seekritModel` as a `model` and
// calls it with `{ requestContext }`) is a type-level and runtime claim verified
// against @mastra/core directly; see the PR for that transcript.
import assert from "node:assert/strict";

import { SeekritError } from "../dist/index.js";
import {
  placeholder,
  scopedFetch,
  seekritModel,
  seekritRequestContext,
  seekritToolFetch,
} from "../dist/mastra.js";

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

const KEYS = { OPENAI_API_KEY: "sk-live-abc", STRIPE_SECRET_KEY: "sk_test_stripe" };

/** A Mastra RequestContext, as far as this adapter is concerned. */
function requestContext(values) {
  return { get: (key) => values[key] };
}

/** Records every resolve, and which overrides it was built for. */
function clientFactory(valuesFor) {
  const calls = [];
  const factory = (overrides) => {
    calls.push(overrides);
    return { resolve: async () => ({ ...valuesFor(overrides) }) };
  };
  factory.calls = calls;
  return factory;
}

function recorder() {
  const seen = [];
  const impl = async (input, init) => {
    const headers = new Headers(init?.headers);
    seen.push({ url: String(input), auth: headers.get("authorization"), all: headers });
    return new Response("{}", { status: 200 });
  };
  return { seen, impl };
}

await check("placeholder builds the marker and rejects an unusable name", () => {
  assert.equal(placeholder("OPENAI_API_KEY"), "{{seekrit:OPENAI_API_KEY}}");
  assert.throws(() => placeholder("bad-name"), SeekritError);
  assert.throws(() => placeholder(""), SeekritError);
});

await check("seekritModel hands the builder a placeholder and a scoped fetch", async () => {
  const { seen, impl } = recorder();
  const client = clientFactory((o) => ({ OPENAI_API_KEY: `sk-${o?.tenants ?? "none"}` }));
  const built = [];
  const model = seekritModel(
    (credentials) => {
      built.push(credentials);
      return credentials;
    },
    {
      secret: "OPENAI_API_KEY",
      allow: { "api.openai.com": ["OPENAI_API_KEY"] },
      client,
      fetch: impl,
      scope: (rc) => ({ with: { tenants: String(rc.get("tenant")) } }),
    },
  );

  const credentials = model({ requestContext: requestContext({ tenant: "northwind" }) });
  assert.equal(credentials.apiKey, "{{seekrit:OPENAI_API_KEY}}");
  assert.deepEqual(credentials.scope, { with: { tenants: "northwind" } });

  await credentials.fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: { authorization: `Bearer ${credentials.apiKey}` },
  });
  assert.equal(seen[0].auth, "Bearer sk-northwind");
  assert.deepEqual(client.calls, [{ tenants: "northwind" }]);
  assert.equal(built.length, 1);
});

await check("one scope reuses one fetch, so the resolve is cached", async () => {
  const { impl } = recorder();
  let resolves = 0;
  const client = () => ({
    resolve: async () => {
      resolves++;
      return { ...KEYS };
    },
  });
  const model = seekritModel((c) => c, {
    secret: "OPENAI_API_KEY",
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client,
    fetch: impl,
    scope: (rc) => ({ with: { tenants: String(rc.get("tenant")) } }),
  });

  const rc = requestContext({ tenant: "northwind" });
  const first = model({ requestContext: rc });
  const second = model({ requestContext: rc });
  // The builder runs per request; the fetch behind it is the same object.
  assert.notEqual(first, second);
  assert.equal(first.fetch, second.fetch, "same scope must share one fetch");

  const init = { headers: { authorization: `Bearer ${first.apiKey}` } };
  await first.fetch("https://api.openai.com/v1/responses", init);
  await second.fetch("https://api.openai.com/v1/responses", init);
  assert.equal(resolves, 1, "two requests, one resolve");
});

await check("a different scope gets its own fetch and its own resolve", async () => {
  const { seen, impl } = recorder();
  const client = clientFactory((o) => ({ OPENAI_API_KEY: `sk-${o?.tenants}` }));
  const model = seekritModel((c) => c, {
    secret: "OPENAI_API_KEY",
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client,
    fetch: impl,
    scope: (rc) => ({ with: { tenants: String(rc.get("tenant")) } }),
  });

  const a = model({ requestContext: requestContext({ tenant: "northwind" }) });
  const b = model({ requestContext: requestContext({ tenant: "lumen" }) });
  assert.notEqual(a.fetch, b.fetch, "different tenants must not share a fetch");

  await a.fetch("https://api.openai.com/v1/responses", {
    headers: { authorization: `Bearer ${a.apiKey}` },
  });
  await b.fetch("https://api.openai.com/v1/responses", {
    headers: { authorization: `Bearer ${b.apiKey}` },
  });
  assert.deepEqual(
    seen.map((s) => s.auth),
    ["Bearer sk-northwind", "Bearer sk-lumen"],
  );
  assert.deepEqual(client.calls, [{ tenants: "northwind" }, { tenants: "lumen" }]);
});

await check("maxScopes bounds the cache, least-recently-used first", async () => {
  const { impl } = recorder();
  const make = scopedFetch(
    { allow: { "api.openai.com": ["OPENAI_API_KEY"] }, client: () => ({ resolve: async () => KEYS }), fetch: impl },
    2,
  );
  const a = make({ with: { tenants: "a" } });
  const b = make({ with: { tenants: "b" } });
  assert.equal(make({ with: { tenants: "a" } }), a, "still cached");
  make({ with: { tenants: "c" } }); // evicts the least-recently-used, which is b
  assert.equal(make({ with: { tenants: "a" } }), a, "a was touched, so it survives");
  assert.notEqual(make({ with: { tenants: "b" } }), b, "b was evicted");
});

await check("seekritToolFetch narrows to the tool's own secrets", async () => {
  const { seen, impl } = recorder();
  const toolFetch = seekritToolFetch({
    allow: { "api.stripe.com": ["STRIPE_SECRET_KEY", "OPENAI_API_KEY"] },
    only: ["STRIPE_SECRET_KEY"],
    client: () => ({ resolve: async () => KEYS }),
    fetch: impl,
    label: "tool:refund",
  });

  const fetch = toolFetch({ requestContext: requestContext({ tenant: "northwind" }) });
  await fetch("https://api.stripe.com/v1/refunds", {
    method: "POST",
    headers: { authorization: "Bearer {{seekrit:STRIPE_SECRET_KEY}}" },
  });
  assert.equal(seen[0].auth, "Bearer sk_test_stripe");

  // The model key is on the host's allowlist but not this tool's.
  const refused = await fetch("https://api.stripe.com/v1/refunds", {
    method: "POST",
    headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
  });
  assert.equal(refused.status, 403);
  assert.equal(refused.headers.get("x-seekrit-secret"), "OPENAI_API_KEY");
  assert.equal(seen.length, 1, "the refused call never reached the upstream");
});

await check("seekritToolFetch still narrows with no request context", async () => {
  const { impl } = recorder();
  const toolFetch = seekritToolFetch({
    allow: { "api.stripe.com": ["STRIPE_SECRET_KEY", "OPENAI_API_KEY"] },
    only: ["STRIPE_SECRET_KEY"],
    client: () => ({ resolve: async () => KEYS }),
    fetch: impl,
  });
  const refused = await toolFetch()("https://api.stripe.com/v1/refunds", {
    method: "POST",
    headers: { authorization: "Bearer {{seekrit:OPENAI_API_KEY}}" },
  });
  assert.equal(refused.status, 403, "a tool's ceiling does not depend on its caller");
});

await check("seekritRequestContext lifts a header into the request context", async () => {
  const middleware = seekritRequestContext({ header: "x-tenant", key: "tenant" });
  const written = {};
  const ctx = {
    req: { header: (name) => (name === "x-tenant" ? "northwind" : undefined) },
    get: () => ({
      set: (k, v) => {
        written.set = [k, v];
      },
      setRaw: (k, v) => {
        written.setRaw = [k, v];
      },
    }),
  };
  let nexted = false;
  await middleware(ctx, async () => {
    nexted = true;
  });
  assert.deepEqual(written.setRaw, ["tenant", "northwind"], "setRaw is preferred");
  assert.equal(written.set, undefined);
  assert.equal(nexted, true);
});

await check("seekritRequestContext falls back to set, and no-ops without the header", async () => {
  const middleware = seekritRequestContext();
  const calls = [];
  const withoutRaw = { set: (k, v) => calls.push([k, v]) };
  await middleware(
    { req: { header: (n) => (n === "x-seekrit-tenant" ? "lumen" : undefined) }, get: () => withoutRaw },
    async () => {},
  );
  assert.deepEqual(calls, [["tenant", "lumen"]]);

  calls.length = 0;
  await middleware({ req: { header: () => undefined }, get: () => withoutRaw }, async () => {});
  assert.deepEqual(calls, [], "no header, nothing written");
});

await check("a single client cannot serve a re-scoped request, and says so", async () => {
  const { impl } = recorder();
  const model = seekritModel((c) => c, {
    secret: "OPENAI_API_KEY",
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    // An object, not a function — bound to its own overrides.
    client: { resolve: async () => KEYS },
    fetch: impl,
    scope: (rc) => ({ with: { tenants: String(rc.get("tenant")) } }),
  });
  const credentials = model({ requestContext: requestContext({ tenant: "northwind" }) });
  await assert.rejects(
    () =>
      credentials.fetch("https://api.openai.com/v1/responses", {
        headers: { authorization: `Bearer ${credentials.apiKey}` },
      }),
    (err) => {
      assert.ok(err instanceof SeekritError);
      assert.match(err.message, /cannot reuse a single `client`/);
      return true;
    },
  );
});

await check("with no scope function, one fetch serves every request", async () => {
  const { impl } = recorder();
  let resolves = 0;
  const model = seekritModel((c) => c, {
    secret: "OPENAI_API_KEY",
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    client: {
      resolve: async () => {
        resolves++;
        return KEYS;
      },
    },
    fetch: impl,
  });
  const a = model({ requestContext: requestContext({}) });
  const b = model({ requestContext: requestContext({}) });
  assert.equal(a.fetch, b.fetch);
  assert.equal(a.scope, undefined);
  const init = { headers: { authorization: `Bearer ${a.apiKey}` } };
  await a.fetch("https://api.openai.com/v1/responses", init);
  await b.fetch("https://api.openai.com/v1/responses", init);
  assert.equal(resolves, 1, "a single-tenant agent resolves once");
});

if (failures > 0) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log("\nall mastra tests passed");
