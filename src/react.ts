/**
 * `@seekrit/sdk/react` — read secrets in a React Server Component, once per
 * render, and make handing one to the client a *render-time error*.
 *
 *     import { secret } from "@seekrit/sdk/react";
 *
 *     export default async function Page() {
 *       const key = await secret("STRIPE_KEY");
 *       const charges = await listCharges(key);
 *       return <Charges rows={charges} />;   // the key does not cross the boundary
 *     }
 *
 * There is deliberately **no client hook**. A `skt_` service token in a client
 * bundle is a published credential, so every path here runs on the server; the
 * client's half of this integration is a `{{seekrit:NAME}}` placeholder and
 * `@seekrit/sdk/route`.
 *
 * Two things make this more than `new Seekrit().resolve()` in a component:
 *
 *   - **One resolve per render.** The resolve is wrapped in React's `cache`, so
 *     twelve components each asking for a secret cost one `/v1/resolve` round
 *     trip, keyed by the group overrides they asked for. This holds inside a
 *     Server Component render, which is what installs the cache dispatcher; in
 *     an SSR pass, a route handler, or plain Node, `cache` has no request to key
 *     on and falls through uncached — still correct, just not deduplicated. If
 *     you want caching *across* requests, that is `seekritFetch`'s `ttlSeconds`,
 *     not this.
 *   - **Taint.** Every resolved value, and the map holding them, is passed to
 *     React's `experimental_taintUniqueValue` / `experimental_taintObjectReference`.
 *     If a value is later passed as a prop to a client component or otherwise
 *     serialized into the RSC payload, React throws *during render* instead of
 *     shipping it. That turns "don't leak the secret" from a convention into a
 *     failing build.
 *
 * **Taint needs enabling.** The taint API is experimental and absent from some
 * React builds; in Next.js it wants `experimental: { taint: true }` in
 * `next.config`. When it is unavailable this module warns once and keeps
 * working — pass `taint: "require"` to make that a hard failure instead, which
 * is the right setting if taint is the reason you are here.
 *
 * `react` is an optional peer dependency, imported only by this entrypoint, so
 * `@seekrit/sdk` itself stays dependency-free.
 */
import * as ReactNamespace from "react";

import { Seekrit, type SeekritOptions } from "./client.js";
import { SeekritError } from "./errors.js";
import type { ResolveSource } from "./fetch.js";
import { withKey } from "./scoped.js";
import { assertServerOnly } from "./server-only.js";
import { protectValues } from "./taint.js";

assertServerOnly("react");

/**
 * The parts of React this file uses, none of which it requires to exist.
 *
 * `cache` is missing on React 18 and the taint functions are missing unless the
 * host app enables them, and both absences should cost a warning rather than a
 * crash on import — so they are read off the namespace rather than named in the
 * import, which also keeps this compiling against any version of the types.
 */
interface ReactRuntime {
  cache?: <A extends unknown[], R>(fn: (...args: A) => R) => (...args: A) => R;
  experimental_taintObjectReference?: (message: string, object: object) => void;
  experimental_taintUniqueValue?: (message: string, lifetime: object, value: string) => void;
}
const react = ReactNamespace as unknown as ReactRuntime;

/** Which slice to resolve. Mirrors `SeekritOptions.with`, per call. */
export interface SecretScope {
  /** `{ groupSlug: envSlug }` overrides — pull a different composed-group slice. */
  with?: Record<string, string>;
}

export interface SeekritReactOptions extends Omit<SeekritOptions, "with"> {
  /**
   * Taint resolved values so React refuses to serialize them to the client
   * (default `true`).
   *
   * `"require"` throws when React's taint API is unavailable instead of warning.
   * Prefer it: believing taint is protecting you when it silently is not is a
   * worse position than knowing it is off.
   */
  taint?: boolean | "require";
  /**
   * Where resolved values come from. Defaults to a {@link Seekrit} built from
   * `token` / `$SEEKRIT_TOKEN` per set of group overrides.
   *
   * Pass a **function** to serve scopes that re-scope: a single client is bound
   * to its own overrides at construction, so it cannot answer for another slice.
   */
  client?: ResolveSource | ((withOverrides: Record<string, string> | undefined) => ResolveSource);
}

export interface SecretReader {
  /** Every secret in scope, as `{ NAME: value }`. One resolve per render. */
  secrets(scope?: SecretScope): Promise<Record<string, string>>;
  /** One secret's value. Throws when it is not in scope — never `undefined`. */
  secret(name: string, scope?: SecretScope): Promise<string>;
  /** One secret's value, or `undefined` when it is not in scope. */
  optionalSecret(name: string, scope?: SecretScope): Promise<string | undefined>;
}

/**
 * Wrap `fn` so calls within one render share a result.
 *
 * The wrap is built on first use rather than at module scope: `cache` keys on
 * the wrapped function's identity, so it must be created once and reused — but
 * creating it eagerly would read `react.cache` before the caller has had a
 * chance to be on a React version that has it.
 */
function memoizePerRender<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
  let wrapped: ((...args: A) => R) | undefined;
  return (...args: A): R => {
    wrapped ??= react.cache ? react.cache(fn) : fn;
    return wrapped(...args);
  };
}

/**
 * Build a reader bound to one token and one taint setting.
 *
 * Nothing is constructed until the first call, so importing this in a component
 * cannot fail a build that has no `SEEKRIT_TOKEN` in its environment yet.
 */
export function createSecretReader(options: SeekritReactOptions = {}): SecretReader {
  const { taint = true, client, ...clientOptions } = options;
  const clients = new Map<string, ResolveSource>();

  function sourceFor(key: string, withOverrides: Record<string, string> | undefined): ResolveSource {
    if (typeof client === "function") return client(withOverrides);
    if (client && !withOverrides) return client;
    if (client) {
      throw new SeekritError(
        "a scope with group overrides cannot reuse a single `client`, which is bound to its own " +
          "overrides: pass `client` as a function of the overrides, or omit it and pass `token`",
      );
    }
    let existing = clients.get(key);
    if (!existing) {
      existing = new Seekrit({ ...clientOptions, with: withOverrides });
      clients.set(key, existing);
    }
    return existing;
  }

  const load = memoizePerRender(async (key: string): Promise<Record<string, string>> => {
    const withOverrides = key
      ? (Object.fromEntries(JSON.parse(key) as [string, string][]) as Record<string, string>)
      : undefined;
    const values = await sourceFor(key, withOverrides).resolve();
    if (taint) {
      protectValues(
        values,
        {
          taintObject: react.experimental_taintObjectReference,
          taintValue: react.experimental_taintUniqueValue,
        },
        taint === "require",
      );
    }
    return values;
  });

  async function secrets(scope?: SecretScope): Promise<Record<string, string>> {
    return load(withKey(scope?.with));
  }

  async function optionalSecret(name: string, scope?: SecretScope): Promise<string | undefined> {
    return (await secrets(scope))[name];
  }

  async function secret(name: string, scope?: SecretScope): Promise<string> {
    const value = await optionalSecret(name, scope);
    if (value === undefined) {
      // Fail closed. A missing secret that reads as `undefined` renders as
      // "undefined" or authenticates as nothing, several frames from the cause.
      throw new SeekritError(
        `secret ${name} is not available to this token${
          scope?.with ? ` in scope ${JSON.stringify(scope.with)}` : ""
        }`,
      );
    }
    return value;
  }

  return { secrets, secret, optionalSecret };
}

const shared = createSecretReader();

/** Every secret in scope, resolved once per render. Token from `$SEEKRIT_TOKEN`. */
export const secrets: SecretReader["secrets"] = shared.secrets;
/** One secret's value, resolved once per render. Throws when it is not in scope. */
export const secret: SecretReader["secret"] = shared.secret;
/** One secret's value, or `undefined` when it is not in scope. */
export const optionalSecret: SecretReader["optionalSecret"] = shared.optionalSecret;

export { placeholder } from "./substitute.js";
export type { SeekritOptions } from "./client.js";
export type { ResolveSource } from "./fetch.js";
