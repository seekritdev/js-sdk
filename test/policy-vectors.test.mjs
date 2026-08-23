// Signed policy bundles, pinned to the same golden fixture the Rust verifier in
// crates/seekrit-core asserts against. Three implementations of one contract:
// @seekrit/core signs, crates/seekrit-core verifies for the proxy, and this SDK
// verifies for a Worker. Regenerate with apps/proxy/testdata/gen-policy-vectors.mts.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  checkPolicyBundleContext,
  checkPolicyCeiling,
  evaluate,
  parsePolicyBundleUnverified,
  policySignerThumbprint,
  SeekritPolicyError,
  verifyPolicyBundle,
} from "../dist/cloudflare-computer.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "..", "testdata", "policy-vectors.json"), "utf8"));

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

const PINNED = vectors.pinned_signers;
/** Well before every vector's expiry, so signature cases are not expiry cases. */
const NOW = 1786000001;

await check("the signer's thumbprint is its pinned id", async () => {
  assert.equal(await policySignerThumbprint(vectors.signer.jwk), vectors.signer.kid);
  assert.ok(PINNED.includes(vectors.signer.kid));
  assert.equal(
    await policySignerThumbprint(vectors.unpinned_signer.jwk),
    vectors.unpinned_signer.kid,
  );
  assert.equal(PINNED.includes(vectors.unpinned_signer.kid), false);
});

for (const vector of vectors.bundles) {
  await check(`bundle: ${vector.label}`, async () => {
    if (!vector.verifies) {
      await assert.rejects(
        () => verifyPolicyBundle(vector.envelope, PINNED),
        SeekritPolicyError,
        `expected ${vector.reject_reason} to be refused`,
      );
      return;
    }

    const bundle = await verifyPolicyBundle(vector.envelope, PINNED);

    if (vector.canonical_body !== undefined) {
      // The signature covers the transported bytes, so what verified must be
      // exactly the body @seekrit/core canonicalized before signing.
      assert.equal(JSON.stringify(bundle), vector.canonical_body);
    }
    if (vector.org !== undefined) assert.equal(bundle.org, vector.org);
    if (vector.agent !== undefined) assert.equal(bundle.agent, vector.agent);
    if (vector.agent_slug !== undefined) assert.equal(bundle.agent_slug, vector.agent_slug);
    if (vector.policy_version !== undefined) {
      assert.equal(bundle.policy_version, vector.policy_version);
    }
    if (vector.expires_at !== undefined) assert.equal(bundle.expires_at, vector.expires_at);
    if (vector.rule_count !== undefined) assert.equal(bundle.rules.length, vector.rule_count);

    // Verification and the context check answer different questions: an expired
    // bundle is correctly signed and still must not be enforced.
    if (vector.expired) {
      assert.throws(() => checkPolicyBundleContext(bundle, { now: NOW }), SeekritPolicyError);
    } else {
      checkPolicyBundleContext(bundle, { now: NOW });
    }
  });
}

await check("an empty pinned list is an error, not a wildcard", async () => {
  const signed = vectors.bundles.find((b) => b.verifies);
  await assert.rejects(() => verifyPolicyBundle(signed.envelope, []), SeekritPolicyError);
});

await check("the context check binds a bundle to its org and agent", async () => {
  const signed = vectors.bundles.find((b) => b.verifies && b.agent);
  const bundle = await verifyPolicyBundle(signed.envelope, PINNED);

  checkPolicyBundleContext(bundle, { now: NOW, org: bundle.org, agent: bundle.agent });
  // The slug is what an operator usually writes in config, so it matches too.
  checkPolicyBundleContext(bundle, { now: NOW, agent: bundle.agent_slug });

  assert.throws(
    () => checkPolicyBundleContext(bundle, { now: NOW, org: "org_someoneElse" }),
    SeekritPolicyError,
  );
  assert.throws(
    () => checkPolicyBundleContext(bundle, { now: NOW, agent: "agt_someoneElse" }),
    SeekritPolicyError,
  );
});

await check("a verified bundle's rules decide exactly what the proxy decides", async () => {
  const signed = vectors.bundles.find((b) => b.rule_count > 0);
  const bundle = await verifyPolicyBundle(signed.envelope, PINNED);
  for (const d of vectors.decisions) {
    const verdict = evaluate(bundle.rules, {
      host: d.host,
      method: d.method,
      path: d.path,
      ...(d.secret === null || d.secret === undefined ? {} : { secret: d.secret }),
    });
    assert.equal(
      verdict.decision,
      d.decision,
      `${d.method} ${d.host}${d.path} ${d.secret ?? "-"}`,
    );
    if (d.rule_index !== null && d.rule_index !== undefined) {
      assert.equal(verdict.ruleIndex, d.rule_index);
    }
  }
});

await check("the ceiling refuses a bundle wholesale rather than narrowing it", async () => {
  const signed = vectors.bundles.find((b) => b.rule_count > 0);
  const bundle = await verifyPolicyBundle(signed.envelope, PINNED);

  // A ceiling that covers every host and name the bundle uses lets it through.
  const generous = {};
  for (const rule of bundle.rules) {
    generous[rule.host] = [...(generous[rule.host] ?? []), ...rule.allow];
  }
  checkPolicyCeiling(bundle.rules, generous);

  // Drop one host: refused, rather than silently running without that rule.
  const { [bundle.rules[0].host]: _dropped, ...missingHost } = generous;
  assert.throws(() => checkPolicyCeiling(bundle.rules, missingHost), SeekritPolicyError);

  // Keep every host, drop one secret name: also refused.
  const named = bundle.rules.find((r) => r.allow.length > 0);
  const narrowed = { ...generous, [named.host]: [] };
  assert.throws(() => checkPolicyCeiling(bundle.rules, narrowed), SeekritPolicyError);
});

await check("parsing without verifying is possible, and clearly named", async () => {
  const tampered = vectors.bundles.find((b) => b.reject_reason === "bad_signature");
  const bundle = parsePolicyBundleUnverified(tampered.envelope);
  assert.ok(Array.isArray(bundle.rules), "readable for display");
  await assert.rejects(() => verifyPolicyBundle(tampered.envelope, PINNED), SeekritPolicyError);
});

if (failures > 0) {
  console.error(`\n${failures} policy vector test(s) failed`);
  process.exit(1);
}
console.log("\nall policy vector tests passed");
