// Functional tests for `@seekrit/sdk/react` — the server-component surface.
//
// Plain script (no test-runner) so it runs identically on every runtime:
//   node test/react.test.mjs
//
// What is NOT covered here, deliberately: per-render deduplication. React's
// `cache` only memoizes once an RSC renderer has installed the cache dispatcher
// — `react-dom/server` does not, nor does calling it from plain Node (verified:
// three calls, three invocations either way). Proving it would mean pulling in
// `react-server-dom-*` and a bundler, so the memoize wrapper is tested for
// identity stability instead, which is the part we own.
import assert from "node:assert/strict";

import { SeekritError } from "../dist/index.js";
import { createSecretReader } from "../dist/react.js";
import { withKey } from "../dist/scoped.js";
import {
  NO_TAINT_WARNING,
  OBJECT_TAINT_MESSAGE,
  protectValues,
  resetTaintWarning,
  valueTaintMessage,
} from "../dist/taint.js";

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

/** A stub resolve source: counts resolves so caching is observable. */
function fakeClient(values) {
  return {
    calls: 0,
    resolve() {
      this.calls++;
      return Promise.resolve({ ...values });
    },
  };
}

/** Swallow the one-time warning so a passing run stays quiet. */
async function withoutWarnings(fn) {
  const original = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(" "));
  try {
    return { result: await fn(), warnings };
  } finally {
    console.warn = original;
  }
}

const KEYS = { DATABASE_URL: "postgres://u:p@host/db", STRIPE_KEY: "sk_live_abc123" };

await check("secret() returns a value and secrets() returns the set", async () => {
  const client = fakeClient(KEYS);
  const { secret, secrets } = createSecretReader({ client, taint: false });
  assert.equal(await secret("STRIPE_KEY"), KEYS.STRIPE_KEY);
  assert.deepEqual(await secrets(), KEYS);
});

await check("secret() fails closed on a name the token cannot see", async () => {
  const { secret, optionalSecret } = createSecretReader({ client: fakeClient(KEYS), taint: false });
  await assert.rejects(() => secret("MISSING"), (error) => {
    assert.ok(error instanceof SeekritError);
    assert.match(error.message, /MISSING is not available/);
    return true;
  });
  // The explicit opt-in is the only way to get `undefined`.
  assert.equal(await optionalSecret("MISSING"), undefined);
});

await check("a rejected resolve reaches the caller", async () => {
  const client = { resolve: () => Promise.reject(new SeekritError("boom")) };
  const { secrets } = createSecretReader({ client, taint: false });
  await assert.rejects(() => secrets(), /boom/);
});

await check("a scope with group overrides gets its own client", async () => {
  const built = [];
  const { secret } = createSecretReader({
    taint: false,
    client: (withOverrides) => {
      built.push(withOverrides);
      return fakeClient({ STRIPE_KEY: `sk_${withOverrides?.tenants ?? "base"}` });
    },
  });
  assert.equal(await secret("STRIPE_KEY"), "sk_base");
  assert.equal(await secret("STRIPE_KEY", { with: { tenants: "acme" } }), "sk_acme");
  assert.deepEqual(built, [undefined, { tenants: "acme" }]);
});

await check("a single client object cannot serve a re-scoped read", async () => {
  const { secret } = createSecretReader({ client: fakeClient(KEYS), taint: false });
  await assert.rejects(
    () => secret("STRIPE_KEY", { with: { tenants: "acme" } }),
    /cannot reuse a single `client`/,
  );
});

await check("scope keys are order-independent", async () => {
  // The key is what `cache` memoizes on, so `{ a, b }` and `{ b, a }` must be
  // one entry rather than two resolves for the same slice.
  assert.equal(withKey({ a: "1", b: "2" }), withKey({ b: "2", a: "1" }));
  assert.notEqual(withKey({ a: "1" }), withKey({ a: "2" }));
  assert.equal(withKey(undefined), "");
});

// --- taint -----------------------------------------------------------------

await check("taint is applied to the map and to every value", async () => {
  const objects = [];
  const values = [];
  const resolved = { ...KEYS };
  protectValues(resolved, {
    taintObject: (message, object) => objects.push({ message, object }),
    taintValue: (message, lifetime, value) => values.push({ message, lifetime, value }),
  });

  assert.equal(objects.length, 1);
  assert.equal(objects[0].message, OBJECT_TAINT_MESSAGE);
  assert.equal(objects[0].object, resolved);

  assert.deepEqual(values.map((v) => v.value).sort(), Object.values(KEYS).sort());
  for (const entry of values) {
    // The lifetime object must be the map: React keeps a value tainted only for
    // as long as the object it was tainted against is reachable.
    assert.equal(entry.lifetime, resolved);
    assert.ok(!entry.message.includes(entry.value), "a taint message must not carry the value");
  }
  const names = Object.keys(KEYS);
  for (const name of names) {
    assert.ok(values.some((v) => v.message === valueTaintMessage(name)), name);
  }
});

await check("React refusing one value does not abort the rest", async () => {
  const tainted = [];
  protectValues(
    { SHORT: "ab", LONG: "sk_live_abc123" },
    {
      taintObject: () => {},
      taintValue: (_message, _lifetime, value) => {
        if (value.length < 8) throw new Error("value is too short to taint");
        tainted.push(value);
      },
    },
  );
  assert.deepEqual(tainted, ["sk_live_abc123"]);
});

await check("no taint API: warn once, keep working", async () => {
  resetTaintWarning();
  const { result, warnings } = await withoutWarnings(async () => {
    const { secret } = createSecretReader({ client: fakeClient(KEYS) });
    return [await secret("STRIPE_KEY"), await secret("DATABASE_URL")];
  });
  assert.deepEqual(result, [KEYS.STRIPE_KEY, KEYS.DATABASE_URL]);
  assert.deepEqual(warnings, [NO_TAINT_WARNING], "exactly one warning, however many reads");
});

await check('taint: "require" refuses to run without the API', async () => {
  resetTaintWarning();
  const { secret } = createSecretReader({ client: fakeClient(KEYS), taint: "require" });
  await assert.rejects(() => secret("STRIPE_KEY"), (error) => {
    assert.ok(error instanceof SeekritError);
    assert.match(error.message, /exposes no taint API/);
    return true;
  });
});

await check("taint: false asks for nothing and warns about nothing", async () => {
  resetTaintWarning();
  const { warnings } = await withoutWarnings(async () => {
    const { secret } = createSecretReader({ client: fakeClient(KEYS), taint: false });
    return secret("STRIPE_KEY");
  });
  assert.deepEqual(warnings, []);
});

// --- the server-only guard --------------------------------------------------

await check("the browser build of the entrypoint refuses to load", async () => {
  await assert.rejects(() => import("../dist/react.browser.js"), (error) => {
    assert.match(error.message, /server-only/);
    assert.match(error.message, /never reach the browser/);
    return true;
  });
});

if (failures > 0) {
  console.error(`\n${failures} react test(s) failed`);
  process.exit(1);
}
console.log("\nall react tests passed");
