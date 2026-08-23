// The Vite plugin. Vite itself is not a dependency here — every shape the
// plugin touches is declared structurally — so `runVite` below stands in for
// it, in the order Vite actually does things:
//
//   1. run the `config` hooks of user plugins (ours is `enforce: "pre"`),
//   2. read the environment — .env files, then every `process.env` key that
//      matches `envPrefix`, which is what becomes `import.meta.env`,
//   3. run the `configResolved` hooks.
//
// Step 2 is copied from Vite's own `loadEnv` (`for (const key in process.env)
// if (prefixes.some((prefix) => key.startsWith(prefix)))`), because the whole
// exposure contract rests on it: a value written before step 2 can reach the
// browser, and a value written in step 3 cannot. That ordering was verified
// against vite 8's resolveConfig directly; see the PR for that transcript.
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SeekritError } from "../dist/index.js";
import { seekritVite } from "../dist/vite.js";

let failures = 0;
async function check(name, fn) {
  const before = { ...process.env };
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failures++;
    console.error(`FAIL  ${name}\n      ${err.stack ?? err.message}`);
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in before)) delete process.env[key];
    for (const [key, value] of Object.entries(before)) process.env[key] = value;
  }
}

const SECRETS = {
  DATABASE_URL: "postgres://user:pw@db/app",
  STRIPE_SECRET_KEY: "sk_live_dont_publish_me",
  VITE_API_URL: "https://api.example.com",
  VITE_SENTRY_DSN: "https://abc@sentry.io/1",
};

/** A resolve source, recording how many times it was asked. */
function source(values = SECRETS) {
  const calls = [];
  return {
    calls,
    resolve: async () => {
      calls.push(Date.now());
      return { ...values };
    },
  };
}

function logger() {
  const infos = [];
  const warns = [];
  return { infos, warns, info: (m) => infos.push(m), warn: (m) => warns.push(m) };
}

/** Drive the plugin the way Vite drives it. Returns the client-visible env. */
async function runVite(plugin, { command = "serve", mode = "development", ...userConfig } = {}) {
  const log = logger();
  await plugin.config(userConfig, { command, mode });
  const prefixes = Array.isArray(userConfig.envPrefix)
    ? userConfig.envPrefix
    : [userConfig.envPrefix ?? "VITE_"];
  // Vite's loadEnv, as far as process.env is concerned.
  const clientEnv = {};
  for (const key in process.env) {
    if (prefixes.some((prefix) => key.startsWith(prefix))) clientEnv[key] = process.env[key];
  }
  plugin.configResolved({ logger: log });
  return { clientEnv, log };
}

await check("resolves into process.env, and only prefixed names reach the client", async () => {
  const client = source();
  const { clientEnv } = await runVite(seekritVite({ client, log: false }));

  assert.equal(process.env.DATABASE_URL, SECRETS.DATABASE_URL);
  assert.equal(process.env.STRIPE_SECRET_KEY, SECRETS.STRIPE_SECRET_KEY);
  assert.equal(process.env.VITE_API_URL, SECRETS.VITE_API_URL);

  assert.deepEqual(Object.keys(clientEnv).sort(), ["VITE_API_URL", "VITE_SENTRY_DSN"]);
  assert.equal(clientEnv.DATABASE_URL, undefined);
  assert.equal(clientEnv.STRIPE_SECRET_KEY, undefined);
  assert.equal(client.calls.length, 1);
});

await check('expose: "none" keeps every value out of the bundle, not out of the process', async () => {
  const { clientEnv } = await runVite(seekritVite({ client: source(), expose: "none", log: false }));

  assert.deepEqual(Object.keys(clientEnv), []);
  // Withheld names are injected after Vite read its environment, so the dev
  // server, SSR, and vite.config consumers still see them.
  assert.equal(process.env.VITE_API_URL, SECRETS.VITE_API_URL);
  assert.equal(process.env.DATABASE_URL, SECRETS.DATABASE_URL);
});

await check("expose: [names] narrows the prefixed set", async () => {
  const { clientEnv } = await runVite(
    seekritVite({ client: source(), expose: ["VITE_API_URL"], log: false }),
  );
  assert.deepEqual(Object.keys(clientEnv), ["VITE_API_URL"]);
  assert.equal(process.env.VITE_SENTRY_DSN, SECRETS.VITE_SENTRY_DSN);
});

await check("expose cannot widen past the prefix", async () => {
  const plugin = seekritVite({ client: source(), expose: ["DATABASE_URL"], log: false });
  await assert.rejects(() => runVite(plugin), (error) => {
    assert.ok(error instanceof SeekritError);
    assert.match(error.message, /DATABASE_URL/);
    assert.match(error.message, /envPrefix/);
    return true;
  });
  // Nothing was injected on the way to the refusal.
  assert.equal(process.env.DATABASE_URL, undefined);
});

await check("a custom envPrefix decides what is public", async () => {
  const client = source({ PUBLIC_TITLE: "seekrit", APP_SECRET: "s3cr3t", VITE_API_URL: "x" });
  const { clientEnv } = await runVite(seekritVite({ client, log: false }), {
    envPrefix: ["PUBLIC_", "NUXT_PUBLIC_"],
  });
  assert.deepEqual(Object.keys(clientEnv), ["PUBLIC_TITLE"]);
  // VITE_ is not a prefix here, so it is a server-side value like any other.
  assert.equal(process.env.VITE_API_URL, "x");
});

await check("the real process environment wins unless override is set", async () => {
  process.env.VITE_API_URL = "http://localhost:1234";
  process.env.DATABASE_URL = "postgres://local/dev";
  const { clientEnv } = await runVite(seekritVite({ client: source(), log: false }));
  assert.equal(clientEnv.VITE_API_URL, "http://localhost:1234");
  assert.equal(process.env.DATABASE_URL, "postgres://local/dev");

  const { clientEnv: overridden } = await runVite(
    seekritVite({ client: source(), override: true, log: false }),
  );
  assert.equal(overridden.VITE_API_URL, SECRETS.VITE_API_URL);
  assert.equal(process.env.DATABASE_URL, SECRETS.DATABASE_URL);
});

await check("a failed resolve fails the build, unless it is optional", async () => {
  const broken = { resolve: async () => { throw new SeekritError("api unreachable"); } };
  await assert.rejects(() => runVite(seekritVite({ client: broken })), /api unreachable/);

  const { log } = await runVite(seekritVite({ client: broken, optional: true }));
  assert.equal(log.warns.length, 1);
  assert.match(log.warns[0], /no secrets loaded: api unreachable/);
});

await check("the summary names what is public, and no values", async () => {
  const { log } = await runVite(seekritVite({ client: source() }));
  assert.equal(log.infos.length, 1);
  const [summary] = log.infos;
  assert.match(summary, /4 secrets loaded \(client, serve\/development\)/);
  assert.match(summary, /in the client bundle: VITE_API_URL, VITE_SENTRY_DSN/);
  for (const value of Object.values(SECRETS)) assert.ok(!summary.includes(value), summary);
});

await check("a credential-shaped name in the bundle is called out", async () => {
  const client = source({ VITE_STRIPE_SECRET_KEY: "sk_live_oops" });
  const { log } = await runVite(seekritVite({ client }));
  assert.equal(log.warns.length, 1);
  assert.match(log.warns[0], /VITE_STRIPE_SECRET_KEY will be readable by anyone/);
  assert.ok(!log.warns[0].includes("sk_live_oops"));
});

await check("onLoad reports names, never values", async () => {
  const events = [];
  await runVite(seekritVite({ client: source(), log: false, onLoad: (e) => events.push(e) }));
  assert.equal(events.length, 1);
  assert.deepEqual(events[0], {
    names: ["DATABASE_URL", "STRIPE_SECRET_KEY", "VITE_API_URL", "VITE_SENTRY_DSN"],
    exposed: ["VITE_API_URL", "VITE_SENTRY_DSN"],
    source: "client",
    command: "serve",
    mode: "development",
  });
});

await check("the worker config pass reuses the first resolve, and reports once", async () => {
  const client = source();
  const events = [];
  const plugin = seekritVite({ client, log: false, onLoad: (e) => events.push(e) });
  await runVite(plugin);
  await runVite(plugin, { command: "build", mode: "production" });
  assert.equal(client.calls.length, 1);
  assert.equal(events.length, 1);
});

await check("no token and no CLI is an error that says what to do", async () => {
  delete process.env.SEEKRIT_TOKEN;
  const plugin = seekritVite({ cliPath: join(tmpdir(), "seekrit-does-not-exist-here") });
  await assert.rejects(() => runVite(plugin), (error) => {
    assert.ok(error instanceof SeekritError);
    assert.match(error.message, /is not on PATH/);
    assert.match(error.message, /SEEKRIT_TOKEN/);
    return true;
  });
});

await check("the CLI source shells out to `seekrit export --format json`", async () => {
  const dir = mkdtempSync(join(tmpdir(), "seekrit-vite-"));
  const fake = join(dir, "seekrit");
  // Records its argv so the flags are asserted, and answers with the export.
  writeFileSync(
    fake,
    `#!/bin/sh\nprintf '%s\\n' "$@" > "${dir}/argv"\ncat <<'JSON'\n${JSON.stringify(SECRETS, null, 2)}\nJSON\n`,
  );
  chmodSync(fake, 0o755);

  delete process.env.SEEKRIT_TOKEN;
  const { clientEnv, log } = await runVite(
    seekritVite({ cliPath: fake, app: "storefront", env: "development", with: { shared: "prod" } }),
  );

  const { readFileSync } = await import("node:fs");
  assert.deepEqual(readFileSync(join(dir, "argv"), "utf8").trim().split("\n"), [
    "export",
    "--format",
    "json",
    "--app",
    "storefront",
    "--env",
    "development",
    "--with",
    "shared=prod",
  ]);
  assert.equal(process.env.DATABASE_URL, SECRETS.DATABASE_URL);
  assert.deepEqual(Object.keys(clientEnv).sort(), ["VITE_API_URL", "VITE_SENTRY_DSN"]);
  assert.match(log.infos[0], /\(cli, serve\/development\)/);
});

await check("a CLI that fails is not silently an empty environment", async () => {
  const dir = mkdtempSync(join(tmpdir(), "seekrit-vite-"));
  const fake = join(dir, "seekrit");
  writeFileSync(fake, "#!/bin/sh\nexit 3\n");
  chmodSync(fake, 0o755);
  delete process.env.SEEKRIT_TOKEN;
  await assert.rejects(() => runVite(seekritVite({ cliPath: fake })), /exited with code 3/);
});

console.log(failures === 0 ? "\nvite: all good" : `\nvite: ${failures} failing`);
process.exit(failures === 0 ? 0 : 1);
