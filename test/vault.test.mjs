// `@seekrit/sdk/vault` — the platform SDK, against a stub hosted API and a stub
// executor. The one property that matters most is pinned first: the Connect
// link's `x` and `k` come from the *executor*, never from the API's response.
//
//   node test/vault.test.mjs
import assert from "node:assert/strict";

import { buildConnectUrl, Vault, VaultExecutorError, verifyWebhook } from "../dist/vault.js";

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

const THUMB = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U";

/** A fake world: the hosted API at api.test, the executor at vault.instinct.test. */
function world() {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    calls.push({ url: u.href, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body });
    const json = (status, body, headers = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
    if (u.origin === "https://vault.instinct.test") {
      if (u.pathname === "/v1/identity") return json(200, { origin: "https://vault.instinct.test", thumbprint: THUMB });
      if (u.pathname === "/v1/browser/open") {
        return json(201, { leaseId: "vls_1_x", sessionId: "bs_1", targetId: "t_1", expiresAt: "2026-10-04T13:00:00.000Z", signedIn: true });
      }
      if (u.pathname === "/v1/browser/release") {
        return json(200, { saved: true, signedIn: true });
      }
      if (u.pathname === "/v1/fetch") {
        const body = JSON.parse(init.body);
        if (body.userRef === "u_other") {
          return json(403, { error: { code: "user_mismatch", message: "nope" } }, { "x-seekrit-vault-error": "user_mismatch" });
        }
        return new Response("provider said hi [redacted]", { status: 201, headers: { "x-upstream": "yes" } });
      }
    }
    if (u.origin === "https://api.test") {
      if (u.pathname === "/v1/vault/connect-sessions" && init.method === "POST") {
        return json(201, {
          session: {
            id: "vcs_1",
            token: "vct_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            expiresAt: "2026-10-04T13:00:00.000Z",
            method: "api_key",
            connectionId: "vcn_1",
            // A compromised API trying to steer the link elsewhere. Must be ignored.
            executorOrigin: "https://evil.test",
            keyThumbprint: "x".repeat(43),
          },
        });
      }
      if (u.pathname === "/v1/vault/manage-sessions" && init.method === "POST") {
        return json(201, { session: { id: "vcs_m", token: "vct_manageABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", expiresAt: "2026-10-04T13:00:00.000Z" } });
      }
      if (u.pathname === "/v1/vault/webhooks" && init.method === "POST") {
        return json(201, { endpoint: { id: "vwh_1", url: JSON.parse(init.body).url, events: ["connection.ready"] }, secret: "whsec_test" });
      }
      if (u.pathname === "/v1/vault/connect-sessions/vcs_1") {
        return json(200, { session: { id: "vcs_1", status: "completed", connectionId: "vcn_1" } });
      }
      if (u.pathname === "/v1/vault/connections" && init.method === "GET") {
        return json(200, { connections: [{ id: "vcn_1", status: "active" }], nextCursor: null });
      }
      if (u.pathname === "/v1/vault/connections/vcn_1" && init.method === "DELETE") {
        return json(200, { connection: { id: "vcn_1", status: "revoked" } });
      }
      return json(404, { error: { code: "not_found", message: "no" } });
    }
    return new Response("unexpected", { status: 500 });
  };
  const vault = new Vault({
    key: "skv_test_key",
    apiUrl: "https://api.test",
    executorUrl: "https://vault.instinct.test/",
    executorToken: "exec-token",
    fetch: fetchImpl,
  });
  return { vault, calls };
}

await check("builds the Connect link with everything in the fragment", () => {
  const url = buildConnectUrl({ token: "vct_t", executorOrigin: "https://vault.instinct.test", keyThumbprint: THUMB });
  const parsed = new URL(url);
  assert.equal(parsed.origin + parsed.pathname, "https://connect.seekrit.dev/");
  assert.equal(parsed.search, "");
  const frag = new URLSearchParams(parsed.hash.slice(1));
  assert.equal(frag.get("t"), "vct_t");
  assert.equal(frag.get("x"), "https://vault.instinct.test");
  assert.equal(frag.get("k"), THUMB);
  assert.throws(() => buildConnectUrl({ token: "t", executorOrigin: "https://vault.instinct.test/path", keyThumbprint: THUMB }));
});

await check("connect.create pins x and k from the executor, not from the API", async () => {
  const { vault, calls } = world();
  const created = await vault.connect.create({ userRef: "u_123", providerId: "resend" });
  assert.equal(created.id, "vcs_1");
  assert.equal(created.connectionId, "vcn_1");
  const frag = new URLSearchParams(new URL(created.url).hash.slice(1));
  assert.equal(frag.get("x"), "https://vault.instinct.test");
  assert.equal(frag.get("k"), THUMB);
  assert.ok(!created.url.includes("evil.test"));
  // The platform key went to the API and the executor token to the executor — never crossed.
  const toApi = calls.find((c) => c.url.startsWith("https://api.test/"));
  const toExecutor = calls.find((c) => c.url.startsWith("https://vault.instinct.test/"));
  assert.equal(toApi.headers.authorization, "Bearer skv_test_key");
  assert.equal(toExecutor.headers.authorization, "Bearer exec-token");
  // Identity is cached.
  await vault.connect.create({ userRef: "u_123", providerId: "resend" });
  assert.equal(calls.filter((c) => c.url.endsWith("/v1/identity")).length, 1);
});

await check("connect.get and connections.* talk to the hosted API", async () => {
  const { vault } = world();
  assert.equal((await vault.connect.get("vcs_1")).status, "completed");
  assert.equal((await vault.connections.list({ userRef: "u_123" })).connections.length, 1);
  assert.equal((await vault.connections.revoke("vcn_1")).status, "revoked");
});

await check("fetch returns the provider's response and surfaces executor refusals as errors", async () => {
  const { vault, calls } = world();
  const res = await vault.fetch({
    userRef: "u_123",
    connectionId: "vcn_1",
    request: { method: "POST", url: "https://api.resend.com/emails", body: "{}" },
  });
  assert.equal(res.status, 201);
  assert.equal(res.headers.get("x-upstream"), "yes");
  assert.equal(await res.text(), "provider said hi [redacted]");
  const sent = JSON.parse(calls.at(-1).body);
  assert.equal(sent.request.url, "https://api.resend.com/emails");
  assert.ok(!("key" in sent), "no credential travels with the request");

  await assert.rejects(
    vault.fetch({ userRef: "u_other", connectionId: "vcn_1", request: { method: "GET", url: "https://api.resend.com/emails" } }),
    (err) => err instanceof VaultExecutorError && err.code === "user_mismatch" && err.status === 403,
  );
});

await check("refuses to start without the three settings, or with a service token", () => {
  assert.throws(() => new Vault({ key: "skt_not_a_platform_key", executorUrl: "https://x.test", executorToken: "t" }), /skv_/);
  assert.throws(() => new Vault({ key: "skv_x", executorToken: "t" }), /VAULT_EXECUTOR_URL/);
  assert.throws(() => new Vault({ key: "skv_x", executorUrl: "https://x.test" }), /VAULT_EXECUTOR_TOKEN/);
});

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall vault tests passed");

await check("manage links are pinned to the executor like connect links", async () => {
  const { vault } = world();
  const link = await vault.manage.create({ userRef: "u_123" });
  const hash = new URL(link.url).hash;
  assert.ok(hash.includes("x=https%3A%2F%2Fvault.instinct.test"));
  assert.ok(hash.includes(`k=${THUMB}`));
  assert.ok(hash.includes("t=vct_manage"));
});

await check("browser leases go to the executor, never the API", async () => {
  const { vault, calls } = world();
  const lease = await vault.browser.open({ userRef: "u_123", connectionId: "vcn_1" });
  assert.equal(lease.sessionId, "bs_1");
  const released = await vault.browser.release({ userRef: "u_123", leaseId: lease.leaseId });
  assert.deepEqual(released, { saved: true, signedIn: true });
  assert.ok(calls.every((c) => !c.url.includes("api.test/v1/browser")));
});

await check("webhook endpoints return the secret once, and verifyWebhook accepts only a matching signature", async () => {
  const { vault } = world();
  const { secret } = await vault.webhooks.create({ url: "https://hooks.instinct.test/vault" });
  assert.equal(secret, "whsec_test");

  // The vector the API's test pins too (packages/core/test/vault.test.ts).
  const body = JSON.stringify({ id: "vwd_1", type: "ping", createdAt: "2026-10-04T12:00:00.000Z", projectId: "vpj_1", data: { connection: null } });
  const timestamp = "1791115200";
  const headers = {
    "seekrit-webhook-id": "vwd_1",
    "seekrit-webhook-timestamp": timestamp,
    "seekrit-webhook-signature": "v1=7d2f2258696d1a73f8ab0fc67a79653d4b98fab33a28e248a23568bdddbd0044",
  };
  const now = Number(timestamp) * 1000;
  const event = await verifyWebhook({ secret: "whsec_test", headers, body, now });
  assert.equal(event?.type, "ping");
  assert.equal(await verifyWebhook({ secret: "whsec_other", headers, body, now }), null);
  assert.equal(await verifyWebhook({ secret: "whsec_test", headers, body: `${body} `, now }), null);
  assert.equal(await verifyWebhook({ secret: "whsec_test", headers, body, now: now + 10 * 60 * 1000 }), null);
});

if (failures > 0) {
  console.error(`${failures} vault check(s) failed`);
  process.exit(1);
}
