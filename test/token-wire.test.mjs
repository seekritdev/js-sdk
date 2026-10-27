import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Seekrit, serviceTokenAuth, TokenKey } from "../dist/index.js";
import { createPolicySource } from "../dist/cloudflare-computer.js";
const v = JSON.parse(readFileSync(new URL("../testdata/vectors.json", import.meta.url)));
const auth = serviceTokenAuth(v.token);
assert.equal(auth, v.authToken);
assert.equal(serviceTokenAuth(auth), auth);
let calls = 0;
const fetch = async (_url, init) => {
  calls++;
  assert.equal(init.headers.authorization, `Bearer ${v.authToken}`);
  assert.ok(!JSON.stringify(init).includes(v.token.split(".")[2]));
  return Response.json(v.resolve);
};
assert.deepEqual(await new Seekrit({ token: v.token, fetch }).resolve(), v.expectedManagedValues);
await assert.rejects(TokenKey.parse(auth));
const legacy = `${v.tokenId}_${v.token.split(".")[2]}`;
assert.equal((await TokenKey.parse(legacy)).tokenId, v.tokenId);
await assert.rejects(new Seekrit({ token: legacy, fetch }).resolve(), /v2 service token/);
for (const invalid of [v.token + ".extra", v.token + "\n", "skt_bad", `${v.tokenId}_v3.${"A".repeat(43)}.key`]) {
  assert.throws(() => serviceTokenAuth(invalid));
}
assert.equal(calls, 1);
console.log("  ok  service token wire boundary and legacy rejection");

let policyCalls = 0;
const policyFetch = async (_url, init) => {
  policyCalls++;
  assert.equal(init.headers.authorization, `Bearer ${v.authToken}`);
  assert.ok(!JSON.stringify(init).includes(v.token.split(".")[2]));
  return new Response("denied", { status: 403 });
};
await assert.rejects(createPolicySource({ token: v.token, agent: "test", signers: ["pinned"], fetch: policyFetch }).current());
await assert.rejects(createPolicySource({ token: legacy, agent: "test", signers: ["pinned"], fetch: policyFetch }).current());
assert.equal(policyCalls, 1);
console.log("  ok  policy requests strip private keys and reject legacy tokens before HTTP");
