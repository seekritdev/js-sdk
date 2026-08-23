/**
 * Vite plugin — a managed environment instead of a `.env` file, with the line
 * between "server-side" and "in the bundle" made explicit.
 *
 *     // vite.config.ts
 *     import { defineConfig } from "vite";
 *     import { seekritVite } from "@seekrit/sdk/vite";
 *
 *     export default defineConfig({
 *       plugins: [seekritVite()],
 *     });
 *
 * Resolving happens in Vite's `config` hook, so every value is in `process.env`
 * before Vite reads its own environment — which means the rest of the pipeline
 * behaves exactly as if a `.env` file had been there: `import.meta.env` for the
 * prefixed names, `process.env` for your config, plugins, SSR handlers, and
 * anything Vitest runs.
 *
 * **The one rule worth internalising: a value in the client bundle is public.**
 * Vite already draws that line at `envPrefix` (`VITE_` by default) and this
 * plugin keeps it exactly where Vite drew it — a resolved secret named
 * `DATABASE_URL` can never reach browser code through this plugin, and there is
 * no option to make it. {@link SeekritViteOptions.expose} only ever narrows the
 * prefixed set, never widens it. The trap is on the other side: a *prefixed*
 * name is client-visible whatever it holds, so `VITE_STRIPE_SECRET_KEY` in your
 * environment is a published credential. The plugin says so at startup rather
 * than letting you find out from a minified bundle.
 *
 * **This is the "wrap the process" rung of the ladder, not the proxy.** Values
 * live in `process.env` of the dev server / build, so anything the build can run
 * can read them — same boundary as `seekrit run -- vite`, which remains a fine
 * way to do this. What the plugin buys is not needing a wrapper: a Vercel or
 * Netlify build, a Vitest run from your editor, or a `vite build` invoked by
 * some other tool all get the environment without anyone remembering a prefix.
 *
 * Nothing here imports `vite`. Every Vite shape is declared structurally below,
 * so the plugin cannot break on a Vite major and `@seekrit/sdk` stays
 * dependency-free.
 */
import { Seekrit } from "./client.js";
import type { ResolveSource } from "./fetch.js";
import { SeekritError } from "./errors.js";

// ── the parts of Vite this plugin touches ─────────────────────────────────

/** A Vite `UserConfig`, as far as this plugin cares. */
export interface UserConfigLike {
  /** Prefix(es) whose variables reach client code. Vite's default is `VITE_`. */
  envPrefix?: string | string[];
  /** Deprecated in Vite 8, but `false` still means "load no env files". */
  envFile?: false;
}

/** What Vite passes as the second argument to a `config` hook. */
export interface ConfigEnvLike {
  command: "serve" | "build";
  mode: string;
}

/** A Vite `ResolvedConfig`, as far as this plugin cares. */
export interface ResolvedConfigLike {
  logger?: { info(message: string): void; warn(message: string): void };
}

/** The plugin object handed back to Vite. Assignable to Vite's `Plugin`. */
export interface SeekritVitePlugin {
  name: string;
  enforce: "pre";
  apply?: "serve" | "build";
  config(config: UserConfigLike, env: ConfigEnvLike): Promise<void>;
  configResolved(config: ResolvedConfigLike): void;
}

// ── options ───────────────────────────────────────────────────────────────

/** Where resolved values come from. */
export type SeekritViteSource = "auto" | "token" | "cli";

export interface SeekritViteLoadEvent {
  /** Every resolved name. Never a value. */
  names: string[];
  /** The subset client code can read, i.e. what ships in the bundle. */
  exposed: string[];
  source: "token" | "cli" | "client";
  command: "serve" | "build";
  mode: string;
}

export interface SeekritViteOptions {
  /**
   * Which resolved names client code may read, within the ones Vite's
   * `envPrefix` already allows:
   *
   * - `"prefixed"` (default) — every resolved name matching the prefix, which
   *   is what Vite would do with the same names in a `.env` file.
   * - `"none"` — no resolved value reaches the bundle. Prefixed names are still
   *   injected, but only after Vite has read its environment, so they are
   *   available to the dev server, SSR, and your config, and to nothing that
   *   gets served.
   * - a list — only these. Every entry must match the prefix; a non-prefixed
   *   name throws, because "expose `DATABASE_URL` to the browser" is never the
   *   thing you meant. Rename the secret if you really want it published.
   */
  expose?: "prefixed" | "none" | string[];
  /**
   * Where values come from (default `"auto"`).
   *
   * `"auto"` uses `$SEEKRIT_TOKEN` (or {@link token}) when one is set, and
   * otherwise shells out to the `seekrit` CLI, which can resolve from your
   * `seekrit login` session — so a teammate who has run `seekrit login` needs no
   * token, and CI needs no CLI. `"token"` and `"cli"` pin one of the two.
   */
  source?: SeekritViteSource;
  /** `skt_…` service token. Defaults to `$SEEKRIT_TOKEN`. */
  token?: string;
  /** API base URL. Defaults to `$SEEKRIT_API_URL`. */
  apiUrl?: string;
  /** `{ groupSlug: envSlug }` overrides — pull a different slice of a group. */
  with?: Record<string, string>;
  /** Expand `${OTHER_SECRET}` references (default `true`). */
  interpolate?: boolean;
  /** CLI source only: which environment to read. A token already names one. */
  app?: string;
  /** CLI source only. */
  env?: string;
  /** CLI source only. */
  branch?: string;
  /** CLI source only. */
  org?: string;
  /** CLI source only: the executable to run (default `seekrit`, from `$PATH`). */
  cliPath?: string;
  /** Resolve through this instead — a preconfigured client, or a test double. */
  client?: ResolveSource;
  /**
   * Overwrite variables already present in `process.env` (default `false`).
   *
   * Off by default so the precedence matches `seekrit run`: the real process
   * environment wins over the managed one, which is what makes
   * `VITE_API_URL=… vite dev` still work as an override.
   */
  override?: boolean;
  /**
   * Start anyway when resolving fails (default `false`).
   *
   * `seekrit run` is best-effort because the command it wraps may not need any
   * of this. A build is the opposite: shipping a bundle whose config silently
   * resolved to `undefined` is worse than not shipping one, so this fails loudly
   * instead. Set `true` for a project where the values are genuinely optional.
   */
  optional?: boolean;
  /** Limit the plugin to the dev server or to builds. Vite's own `apply`. */
  apply?: "serve" | "build";
  /** Print the one-line summary at startup (default `true`). Names only. */
  log?: boolean;
  /** Called once, after resolving. Names only — never values. */
  onLoad?: (event: SeekritViteLoadEvent) => void;
}

// ── environment access ────────────────────────────────────────────────────

/** Node/Bun/Deno-with-node-compat all have this; a browser does not. */
function processEnv(): Record<string, string | undefined> {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
    ?.env;
  if (!env) {
    throw new SeekritError(
      "the seekrit Vite plugin needs a `process.env` to inject into; it runs in the Vite process (Node, Bun, or Deno), not in the browser",
    );
  }
  return env;
}

function readEnv(name: string): string | undefined {
  const g = globalThis as {
    process?: { env?: Record<string, string | undefined> };
    Deno?: { env?: { get(k: string): string | undefined } };
  };
  const fromProcess = g.process?.env?.[name];
  if (typeof fromProcess === "string") return fromProcess;
  try {
    return g.Deno?.env?.get(name) ?? undefined;
  } catch {
    return undefined; // Deno without --allow-env
  }
}

// ── loading ───────────────────────────────────────────────────────────────

/**
 * Resolve through the `seekrit` CLI, which can use a `seekrit login` session.
 *
 * stdin and stderr are inherited on purpose: a session-authenticated export
 * prompts for the passphrase, and a dev server started from a terminal has one
 * to prompt on. `$SEEKRIT_PASSPHRASE` skips it where there isn't.
 */
async function loadFromCli(options: SeekritViteOptions): Promise<Record<string, string>> {
  const { spawn } = await import("node:child_process");
  const command = options.cliPath ?? "seekrit";
  const overrides = options.with ?? {};
  const args = ["export", "--format", "json"];
  if (options.org) args.push("--org", options.org);
  if (options.app) args.push("--app", options.app);
  if (options.env) args.push("--env", options.env);
  if (options.branch) args.push("--branch", options.branch);
  for (const group of Object.keys(overrides).sort()) {
    args.push("--with", `${group}=${overrides[group]}`);
  }
  if (options.interpolate === false) args.push("--no-interpolate");

  const stdout = await new Promise<string>((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["inherit", "pipe", "inherit"] });
    let out = "";
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk) => {
      out += chunk;
    });
    child.on("error", (error) => {
      reject(
        new SeekritError(
          error.code === "ENOENT"
            ? `the \`${command}\` CLI is not on PATH: install it (npm i -g @seekrit/cli), set SEEKRIT_TOKEN, or pass { cliPath }`
            : `\`${command} export\` failed to start: ${error.message}`,
        ),
      );
    });
    child.on("close", (code) => {
      if (code === 0) resolve(out);
      // The CLI already printed its own diagnosis to the inherited stderr, so
      // guessing at one here would only bury it.
      else reject(new SeekritError(`\`${command} export\` exited with code ${code ?? "null"}`));
    });
  });

  try {
    return JSON.parse(stdout) as Record<string, string>;
  } catch (cause) {
    throw new SeekritError(
      `\`${command} export --format json\` printed something that is not JSON: ${String(cause)}`,
    );
  }
}

async function load(
  options: SeekritViteOptions,
): Promise<{ values: Record<string, string>; source: "token" | "cli" | "client" }> {
  if (options.client) return { values: await options.client.resolve(), source: "client" };

  const token = options.token ?? readEnv("SEEKRIT_TOKEN");
  const source = options.source ?? "auto";
  if (source === "cli" || (source === "auto" && !token)) {
    return { values: await loadFromCli(options), source: "cli" };
  }
  if (!token) {
    throw new SeekritError(
      'no service token: set SEEKRIT_TOKEN, pass { token }, or use source: "auto" (the default) to resolve through a `seekrit login` session instead',
    );
  }
  const client = new Seekrit({
    token,
    apiUrl: options.apiUrl,
    with: options.with,
    interpolate: options.interpolate,
  });
  return { values: await client.resolve(), source: "token" };
}

// ── exposure ──────────────────────────────────────────────────────────────

function prefixesOf(config: UserConfigLike): string[] {
  const prefix = config.envPrefix ?? "VITE_";
  return Array.isArray(prefix) ? prefix : [prefix];
}

/** Names that look like a credential, for the warning. Heuristic, not a gate. */
const SENSITIVE_RE = /SECRET|PASSWORD|PASSPHRASE|PRIVATE|CREDENTIAL|_TOKEN\b/;

// ── the plugin ────────────────────────────────────────────────────────────

/**
 * Resolve a seekrit environment into the Vite process.
 *
 * Returns a Vite plugin. Put it anywhere in `plugins`; it declares
 * `enforce: "pre"` so its `config` hook runs before other plugins' and they see
 * a populated `process.env` too.
 */
export function seekritVite(options: SeekritViteOptions = {}): SeekritVitePlugin {
  const expose = options.expose ?? "prefixed";
  const shouldLog = options.log ?? true;

  // Resolve at most once per plugin instance. Vite runs the `config` hook again
  // for the worker config, and a second round trip (or a second passphrase
  // prompt) for the same values would be a surprise.
  let loading: Promise<{ values: Record<string, string>; source: "token" | "cli" | "client" }>;
  /** Prefixed names withheld from the bundle, injected once Vite has read env. */
  let deferred: Array<[string, string]> = [];
  let summary: string | undefined;
  let warning: string | undefined;
  /** Vite runs the hook again for the worker config; `onLoad` means once. */
  let reported = false;

  function assign(env: Record<string, string | undefined>, name: string, value: string): void {
    if (!options.override && env[name] !== undefined) return;
    env[name] = value;
  }

  return {
    name: "seekrit",
    enforce: "pre",
    ...(options.apply ? { apply: options.apply } : {}),

    async config(config: UserConfigLike, { command, mode }: ConfigEnvLike): Promise<void> {
      const prefixes = prefixesOf(config);
      if (Array.isArray(expose)) {
        const stray = expose.filter((name) => !prefixes.some((p) => name.startsWith(p)));
        if (stray.length > 0) {
          throw new SeekritError(
            `expose lists ${stray.join(", ")}, which ${stray.length > 1 ? "do" : "does"} not match Vite's envPrefix (${prefixes.join(", ")}). Only prefixed names can reach client code — rename the secret if you mean to publish it, and drop it from expose if you don't`,
          );
        }
      }

      let values: Record<string, string>;
      let source: "token" | "cli" | "client";
      try {
        loading ??= load(options);
        ({ values, source } = await loading);
      } catch (error) {
        if (!options.optional) throw error;
        warning = `[seekrit] no secrets loaded: ${error instanceof Error ? error.message : String(error)}`;
        return;
      }

      const env = processEnv();
      const names = Object.keys(values).sort();
      const exposed: string[] = [];
      deferred = [];
      for (const name of names) {
        const value = values[name] as string;
        const prefixed = prefixes.some((prefix) => name.startsWith(prefix));
        if (!prefixed) {
          // Vite never puts a non-prefixed name in `import.meta.env`, so this is
          // server-side by construction, whenever we write it.
          assign(env, name, value);
          continue;
        }
        const allowed = expose === "prefixed" || (Array.isArray(expose) && expose.includes(name));
        if (!allowed) {
          // Withheld: write it *after* Vite has read the environment, so it
          // cannot be picked up for the bundle. Failing this way loses a value
          // server-side rather than publishing one, which is the right failure.
          deferred.push([name, value]);
          continue;
        }
        assign(env, name, value);
        exposed.push(name);
      }

      summary =
        `[seekrit] ${names.length} secret${names.length === 1 ? "" : "s"} loaded (${source}, ${command}/${mode})` +
        (exposed.length > 0
          ? ` · in the client bundle: ${exposed.join(", ")}`
          : " · none in the client bundle");

      if (exposed.length > 0 && config.envFile === false) {
        warning = `[seekrit] envFile is false, so this Vite may not read process.env for the bundle: ${exposed.join(", ")} may be missing from import.meta.env`;
      } else {
        const risky = exposed.filter((name) => SENSITIVE_RE.test(name));
        if (risky.length > 0) {
          warning = `[seekrit] ${risky.join(", ")} will be readable by anyone who loads the site — a prefixed name is public. Rename it, or set expose: "none"`;
        }
      }

      if (!reported) {
        reported = true;
        options.onLoad?.({ names, exposed, source, command, mode });
      }
    },

    configResolved(config: ResolvedConfigLike): void {
      if (deferred.length > 0) {
        const env = processEnv();
        for (const [name, value] of deferred) assign(env, name, value);
        deferred = [];
      }
      const logger = config.logger;
      if (warning) {
        if (logger) logger.warn(warning);
        else console.warn(warning);
      }
      if (shouldLog && summary) {
        if (logger) logger.info(summary);
        else console.log(summary);
      }
      warning = undefined;
      summary = undefined;
    },
  };
}
