// Cross-implementation parity: decrypt the shared golden vectors and assert we
// recover exactly what the canonical @seekrit/crypto (WebCrypto) produced.
//
// Plain script (no test-runner) so it runs identically on every runtime:
//   node test/vectors.test.mjs
//   bun  test/vectors.test.mjs
//   deno run --allow-read test/vectors.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  interpolateSecrets,
  materialize,
  SeekritCryptoError,
  SeekritReferenceError,
  TokenKey,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "..", "testdata", "vectors.json"), "utf8"));

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function makeValidButDifferentToken() {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return `skt_AAAAAAAAAAAAAAAAAAAAAA_${toBase64Url(pkcs8)}`;
}

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failures++;
    console.error(`FAIL  ${name}\n      ${err.message}`);
  }
}

const key = await TokenKey.parse(vectors.token);

await check("materialize matches expected", async () => {
  const merged = await materialize(vectors.resolve, key);
  assert.deepEqual(merged, vectors.expectedManagedValues);
});

await check("app layer wins over group", async () => {
  const merged = await materialize(vectors.resolve, key);
  assert.equal(merged.SHARED, "from-app");
});

await check("unicode and empty round-trip", async () => {
  const merged = await materialize(vectors.resolve, key);
  assert.equal(merged.UNICODE, "héllo-🌍-\n-tab\tend");
  assert.equal(merged.EMPTY, "");
});

await check("secret references expand over the merged set", async () => {
  const merged = await materialize(vectors.resolve, key);
  assert.equal(merged.REFERENCING, "url=postgres://group/db;shared=from-app");
  assert.equal(merged.ESCAPED_REF, "${SHARED}");
  assert.equal(merged.DANGLING_REF, "build-${NOT_A_SECRET}");
});

await check("interpolate:false returns the stored text", async () => {
  const merged = await materialize(vectors.resolve, key, { interpolate: false });
  assert.equal(merged.REFERENCING, "url=${DATABASE_URL};shared=${SHARED}");
});

for (const testCase of vectors.interpolation.cases) {
  await check(`interpolation: ${testCase.name}`, () => {
    const { values, unresolved } = interpolateSecrets(testCase.input);
    assert.deepEqual(values, testCase.expected);
    assert.deepEqual(unresolved, testCase.unresolved);
  });
}

for (const testCase of vectors.interpolation.cycles) {
  await check(`interpolation rejects: ${testCase.name}`, () => {
    assert.throws(() => interpolateSecrets(testCase.input), SeekritReferenceError);
  });
}

await check("wrong token cannot unwrap", async () => {
  const wrongKey = await TokenKey.parse(await makeValidButDifferentToken());
  await assert.rejects(() => materialize(vectors.resolve, wrongKey), SeekritCryptoError);
});

if (failures > 0) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log("\nall vector tests passed");
