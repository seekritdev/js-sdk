// The Cloudflare Sandbox entry point. The gateway is the same code the
// Cloudflare Computer adapter exports (cloudflare-computer.test.mjs covers its
// substitution and refusal rules in depth); these tests pin what is specific to
// a Container with outbound intercepts: the shared surface, the CA trust
// environment, and the shapes the guide tells people to write — a module-scope
// gateway behind a per-call WorkerEntrypoint, a header the Worker adds, and
// git over HTTPS, whose Basic credential carries the placeholder base64-encoded.
import assert from "node:assert/strict";

import * as computer from "../dist/cloudflare-computer.js";
import * as sandbox from "../dist/cloudflare-sandbox.js";

const { CONTAINERS_CA_PATH, containerTrustEnv, seekritEgress, seekritEnv } = sandbox;

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

const KEYS = {
  ANTHROPIC_API_KEY: "sk-ant-live",
  AI_GATEWAY_TOKEN: "aig-live",
  GITHUB_TOKEN: "ghp_live",
};

function upstream() {
  const seen = [];
  const impl = async (input, init) => {
    const headers = new Headers(init?.headers);
    seen.push({ url: String(input), method: init?.method, headers });
    return new Response("ok", { status: 200 });
  };
  return { seen, impl };
}

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

await check("the sandbox entry exports the very same gateway as the computer entry", () => {
  for (const name of ["seekritEgress", "seekritEnv", "resolveEnv", "evaluate", "placeholder"]) {
    assert.equal(typeof sandbox[name], "function", name);
    assert.equal(sandbox[name], computer[name], `${name} must be shared, not a copy`);
  }
  assert.equal(sandbox.SeekritError, computer.SeekritError);
});

await check("the Computer-only policy wrapper is not part of the sandbox surface", () => {
  assert.equal(sandbox.seekritEgressPolicy, undefined);
  assert.equal(typeof computer.seekritEgressPolicy, "function");
  assert.equal(computer.containerTrustEnv, undefined);
});

await check("containerTrustEnv points every client family at the containers CA", () => {
  assert.equal(CONTAINERS_CA_PATH, "/etc/cloudflare/certs/cloudflare-containers-ca.crt");
  const env = containerTrustEnv();
  assert.deepEqual(Object.keys(env).sort(), [
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
  ]);
  for (const value of Object.values(env)) assert.equal(value, CONTAINERS_CA_PATH);
  for (const value of Object.values(containerTrustEnv("/tmp/ca.pem"))) {
    assert.equal(value, "/tmp/ca.pem");
  }
});

await check("trust and placeholders compose into one exec env without a value in it", () => {
  const env = { ...seekritEnv(["ANTHROPIC_API_KEY"]), ...containerTrustEnv() };
  assert.equal(env.ANTHROPIC_API_KEY, "{{seekrit:ANTHROPIC_API_KEY}}");
  assert.ok(!Object.values(env).includes(KEYS.ANTHROPIC_API_KEY));
});

// Workers constructs a WorkerEntrypoint for every call. These two classes stand
// in for one, constructed per request exactly as the runtime does.
function entrypoints(client, sent) {
  const options = {
    allow: { "api.anthropic.com": ["ANTHROPIC_API_KEY"] },
    client,
    fetch: sent.impl,
  };

  let egress;
  class ModuleScoped {
    fetch(request) {
      egress ??= seekritEgress(options);
      return egress.fetch(request);
    }
  }
  class ClassField {
    #egress = seekritEgress(options);
    fetch(request) {
      return this.#egress.fetch(request);
    }
  }
  return { ModuleScoped, ClassField };
}

const claudeCall = () =>
  new Request("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": "{{seekrit:ANTHROPIC_API_KEY}}" },
    body: "{}",
  });

await check("a module-scope gateway resolves once across per-call entrypoints", async () => {
  const client = source();
  const sent = upstream();
  const { ModuleScoped } = entrypoints(client, sent);
  for (let i = 0; i < 3; i++) {
    const res = await new ModuleScoped().fetch(claudeCall());
    assert.equal(res.status, 200);
  }
  assert.equal(client.state.calls, 1);
  for (const call of sent.seen) assert.equal(call.headers.get("x-api-key"), KEYS.ANTHROPIC_API_KEY);
});

await check("a class-field gateway resolves on every call — the shape the docs warn off", async () => {
  const client = source();
  const sent = upstream();
  const { ClassField } = entrypoints(client, sent);
  for (let i = 0; i < 3; i++) await new ClassField().fetch(claudeCall());
  assert.equal(client.state.calls, 3);
});

await check("a header the Worker adds with a placeholder is still gated by the rules", async () => {
  // Cloudflare's coding-agent tutorial authenticates to AI Gateway with a header
  // the agent never sends. Adding it as a placeholder keeps the value in the
  // gateway, and the rule still decides which name may go to which path.
  const client = source();
  const sent = upstream();
  const egress = seekritEgress({
    rules: [
      {
        host: "gateway.ai.cloudflare.com",
        paths: ["/v1/acct/gw/**"],
        allow: ["AI_GATEWAY_TOKEN"],
      },
    ],
    client,
    fetch: sent.impl,
  });
  const outbound = (request) => {
    if (new URL(request.url).hostname === "gateway.ai.cloudflare.com") {
      const headers = new Headers(request.headers);
      headers.delete("x-api-key");
      headers.set("cf-aig-authorization", "Bearer {{seekrit:AI_GATEWAY_TOKEN}}");
      request = new Request(request, { headers });
    }
    return egress.fetch(request);
  };

  const ok = await outbound(
    new Request("https://gateway.ai.cloudflare.com/v1/acct/gw/anthropic/v1/messages", {
      method: "POST",
      headers: { "x-api-key": "provided-by-worker" },
      body: "{}",
    }),
  );
  assert.equal(ok.status, 200);
  assert.equal(sent.seen[0].headers.get("cf-aig-authorization"), `Bearer ${KEYS.AI_GATEWAY_TOKEN}`);
  assert.equal(sent.seen[0].headers.get("x-api-key"), null);

  const elsewhere = await outbound(
    new Request("https://gateway.ai.cloudflare.com/v1/someone-else/gw/anthropic"),
  );
  assert.equal(elsewhere.status, 403);
  assert.equal(elsewhere.headers.get("x-seekrit-refusal"), "path_not_allowed");
  assert.equal(sent.seen.length, 1);
});

await check("cleartext HTTP routed to the gateway is refused with a reason", async () => {
  const sent = upstream();
  const egress = seekritEgress({
    allow: { "api.anthropic.com": ["ANTHROPIC_API_KEY"] },
    client: source(),
    fetch: sent.impl,
  });
  const res = await egress.fetch(new Request("http://api.anthropic.com/v1/messages"));
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-seekrit-refusal"), "port_not_allowed");
  assert.equal(sent.seen.length, 0);
});

await check("git over HTTPS: a placeholder inside a Basic credential is injected", async () => {
  // git base64-encodes `user:password` before it leaves the container, so the
  // marker only exists after decoding. The gateway decodes exactly this shape
  // (the `header` cases of the shared vectors; apps/proxy does the same).
  const client = source();
  const sent = upstream();
  const egress = seekritEgress({
    rules: [{ host: "github.com", allow: ["GITHUB_TOKEN"] }],
    client,
    fetch: sent.impl,
  });
  const res = await egress.fetch(
    new Request("https://github.com/acme/app.git/info/refs?service=git-upload-pack", {
      headers: { authorization: `Basic ${btoa("x-access-token:{{seekrit:GITHUB_TOKEN}}")}` },
    }),
  );
  assert.equal(res.status, 200);
  assert.equal(sent.seen[0].headers.get("authorization"), `Basic ${btoa("x-access-token:ghp_live")}`);
  assert.equal(client.state.calls, 1);
});

await check("git over HTTPS: a Basic credential naming a secret no rule allows is refused", async () => {
  const client = source();
  const sent = upstream();
  const egress = seekritEgress({
    rules: [{ host: "github.com", allow: ["GITHUB_TOKEN"] }],
    client,
    fetch: sent.impl,
  });
  const res = await egress.fetch(
    new Request("https://github.com/acme/app.git/info/refs?service=git-upload-pack", {
      headers: { authorization: `Basic ${btoa("x-access-token:{{seekrit:ANTHROPIC_API_KEY}}")}` },
    }),
  );
  assert.equal(res.status, 403);
  assert.equal(sent.seen.length, 0);
});

if (failures > 0) {
  console.error(`\n${failures} cloudflare-sandbox test(s) failed`);
  process.exit(1);
}
console.log("\nall cloudflare-sandbox tests passed");
