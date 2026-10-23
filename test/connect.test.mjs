import assert from "node:assert/strict";
import { createWorkloadKey, SeekritConnect } from "../dist/connect.js";

const pair = await createWorkloadKey();
assert.equal(pair.publicKey.d, undefined);
const publicKey = await crypto.subtle.importKey("jwk", pair.publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
const scope = { repositoryIds: [42], permissions: { contents: "read" } };
const json = (value, status = 200) => Response.json(value, { status });

function world() {
  const calls = [];
  const assertions = [];
  let reject = false;
  let lifetime = 300;
  const client = new SeekritConnect({ workloadId: "wli_sdk", signingKey: pair.privateKey,
    issuer: "https://issuer.example", fetch: async (url, init) => {
      calls.push({ url, ...init });
      assert.equal(init.redirect, "error");
      assert.ok(!init.body.includes(pair.privateKey.d), "private key is never transmitted");
      if (url.endsWith("/oauth/token")) {
        const form = new URLSearchParams(init.body);
        assert.equal(form.get("grant_type"), "client_credentials");
        assert.equal(form.get("scope"), "connect");
        const assertion = form.get("client_assertion");
        const [header, payload, signature] = assertion.split(".");
        assert.equal(JSON.parse(Buffer.from(header, "base64url")).alg, "ES256");
        assert.ok(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey,
          Buffer.from(signature, "base64url"), new TextEncoder().encode(`${header}.${payload}`)));
        const claims = JSON.parse(Buffer.from(payload, "base64url"));
        assert.equal(claims.iss, "wli_sdk");
        assert.equal(claims.sub, "wli_sdk");
        assert.equal(claims.aud, "https://issuer.example/oauth/token");
        assert.equal(claims.exp - claims.iat, 60);
        assert.ok(!assertions.includes(claims.jti), "every exchange signs a new assertion");
        assertions.push(claims.jti);
        return json({ access_token: `session-${assertions.length}`, expires_in: lifetime, token_type: "Bearer" });
      }
      if (reject) return json({ error: "unauthorized" }, 401);
      assert.equal(init.headers.authorization, `Bearer session-${assertions.length}`);
      if (url.endsWith("/identity-token")) return json({ token: "identity", expiresIn: 300 });
      if (url.endsWith("/token")) return json({ accessToken: "github-installation", expiresAt: "2030-01-01T01:00:00Z", ...scope });
      return json({ status: 201, contentType: "application/json", body: '{"id":"email-1"}' });
    } });
  return { client, calls, assertions, reject: (value) => { reject = value; }, lifetime: (value) => { lifetime = value; } };
}

const first = world();
const tokens = await Promise.all(Array.from({ length: 8 }, () => first.client.getToken("ccn_github", scope)));
assert.equal(first.assertions.length, 1, "concurrent calls share a session exchange");
assert.equal(tokens[0].accessToken, "github-installation");
assert.deepEqual(JSON.parse(first.calls.at(-1).body), scope, "scope is explicit and unmodified");
await first.client.getIdentityToken("sts.amazonaws.com");
assert.deepEqual(JSON.parse(first.calls.at(-1).body), { audience: "sts.amazonaws.com" });
const response = await first.client.proxy("ccn_resend", { path: "/emails", method: "POST", body: '{"subject":"test"}' });
assert.equal(response.status, 201);
assert.equal(response.headers.get("cache-control"), "no-store");
assert.deepEqual(await response.json(), { id: "email-1" });
assert.equal(first.assertions.length, 1, "cached session is reused");

first.reject(true);
const before = first.calls.length;
await assert.rejects(first.client.proxy("ccn_resend", { path: "/emails", method: "POST", body: "{}" }), /401/);
assert.equal(first.calls.length, before + 1, "mutating requests are never automatically replayed");
first.reject(false);
await first.client.getToken("ccn_github", scope);
assert.equal(first.assertions.length, 2, "a 401 clears the session for the next explicit request");

const expiring = world();
expiring.lifetime(20);
await expiring.client.getToken("ccn_github", scope);
await expiring.client.getToken("ccn_github", scope);
assert.equal(expiring.assertions.length, 2, "sessions refresh before expiry");
const invalid = world();
invalid.lifetime(3600);
await assert.rejects(invalid.client.getToken("ccn_github", scope), /Invalid Seekrit workload session/);
assert.equal(invalid.calls.length, 1, "invalid sessions cannot reach a connector");

for (const issuer of ["http://issuer.example", "https://issuer.example/path", "https://user:pass@issuer.example", "https://issuer.example?x=1"]) {
  assert.throws(() => new SeekritConnect({ workloadId: "wli_sdk", signingKey: pair.privateKey, issuer }), /HTTPS origin/);
}
console.log("all connect SDK tests passed (signed assertions, session caching, scope forwarding, proxy responses, replay avoidance)");
