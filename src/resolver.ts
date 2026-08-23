/**
 * One resolve, shared by every injection surface.
 *
 * Both {@link seekritFetch} and {@link seekritEgress} need the same three
 * things: build a client for a set of group overrides, resolve through it, and
 * keep the answer for a TTL so a busy agent does not make one metered
 * `/v1/resolve` call per outbound request. Keeping that in one place is the
 * point — a cache that expires differently on two paths is a bug you find in
 * production, at rotation time.
 *
 * Values live in memory only, and a failed resolve is never cached.
 */
import { Seekrit } from "./client.js";
import { SeekritError } from "./errors.js";

/** The one method a resolve source must have. `Seekrit` satisfies it. */
export interface ResolveSource {
  resolve(): Promise<Record<string, string>>;
}

/**
 * Where resolved values come from.
 *
 * A single client is bound to one set of group overrides at construction, so it
 * can only serve callers that do not re-scope: pass a **function** when the
 * overrides vary, and it is called with them to produce the right client.
 */
export type ClientSource =
  | ResolveSource
  | ((withOverrides: Record<string, string> | undefined) => ResolveSource);

export interface ResolverOptions {
  /** `skt_…` service token. Defaults to `$SEEKRIT_TOKEN`. */
  token?: string;
  /** API base URL. Defaults to `$SEEKRIT_API_URL`. */
  apiUrl?: string;
  /** Where resolved values come from. Omit to build a client per override set. */
  client?: ClientSource;
  /**
   * How long a resolved set may be reused, per override set (default 60). `0`
   * resolves on every request that needs a value — correct, and one extra round
   * trip each time.
   */
  ttlSeconds?: number;
  /** The fetch the built client resolves with. */
  fetch?: typeof globalThis.fetch;
}

/** Resolve for one set of group overrides, cached for the TTL. */
export type Resolver = (
  withOverrides?: Record<string, string>,
) => Promise<Record<string, string>>;

export function createResolver(options: ResolverOptions): Resolver {
  const ttlMs = Math.max(0, options.ttlSeconds ?? 60) * 1000;
  const cache = new Map<string, { expires: number; values: Promise<Record<string, string>> }>();

  /**
   * The resolve source for one override set.
   *
   * The awkward case is a caller who passed a single `client` *and* overrides:
   * that client is bound to its own overrides and cannot be re-scoped, so
   * silently using it would resolve the wrong tenant. If a token is available we
   * build a correctly-scoped client; if not, say exactly that rather than
   * surfacing "no service token" from three frames down.
   */
  function clientFor(withOverrides: Record<string, string> | undefined): ResolveSource {
    if (typeof options.client === "function") return options.client(withOverrides);
    if (options.client && !withOverrides) return options.client;
    try {
      return new Seekrit({
        token: options.token,
        apiUrl: options.apiUrl,
        with: withOverrides,
        fetch: options.fetch,
      });
    } catch (cause) {
      if (options.client) {
        throw new SeekritError(
          "a scope with group overrides cannot reuse a single `client`, which is bound to its " +
            "own overrides: pass `client` as a function of the overrides, or pass `token` so a " +
            "scoped client can be built",
        );
      }
      throw cause;
    }
  }

  return (withOverrides) => {
    const key = withOverrides ? JSON.stringify(Object.entries(withOverrides).sort()) : "";
    const hit = cache.get(key);
    const now = Date.now();
    if (hit && hit.expires > now) return hit.values;

    const values = clientFor(withOverrides)
      .resolve()
      .catch((error: unknown) => {
        cache.delete(key); // never cache a failure
        throw error;
      });
    if (ttlMs > 0) cache.set(key, { expires: now + ttlMs, values });
    return values;
  };
}
