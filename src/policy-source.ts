/**
 * Keeping a verified policy bundle current inside a Worker.
 *
 * The proxy is a long-lived process: it fetches every agent's bundle at start
 * and re-fetches on a timer. A Worker has no "start" and no timer — it is a
 * swarm of short-lived isolates — so the same job needs a different shape.
 *
 * Three layers, each optional above the first:
 *
 * 1. **In-isolate memory** (always). A verified bundle is held in the closure
 *    and reused for `refreshSeconds`. Costs nothing and needs no bindings, but
 *    each isolate refreshes on its own, so a busy Worker makes many small
 *    conditional requests. Cheap ones: the fetch is `If-None-Match`, and the
 *    steady state is a 304.
 * 2. **A {@link PolicyStore}** (optional) in front of the API — KV, the Cache
 *    API, a Durable Object, anything with get/put. This is what turns "per
 *    isolate" into "per colo" or "per account". Its own TTL is the real
 *    cross-isolate refresh interval.
 * 3. **`waitUntil`** (optional). With it, a refresh that comes due while a
 *    usable bundle is still in hand happens in the background and no request
 *    waits for it. Without it, that request awaits the refresh, because a
 *    promise left running after a Worker responds may simply be cancelled.
 *
 * **None of these layers is the safety boundary.** `expires_at` is: a bundle is
 * refused once it passes, whatever any cache says, so the blast radius of a
 * stale cache is bounded by the TTL you published with — not by how often
 * anything polls. Refresh cadence decides how fast a *narrowing* lands. Bundle
 * TTL decides how long a *revocation* can be ignored. Tune them separately.
 */
import { SeekritError } from "./errors.js";
import {
  checkPolicyBundleContext,
  checkPolicyCeiling,
  type PolicyBundle,
  type PolicyBundleRule,
  type PolicyCeiling,
  SeekritPolicyError,
  verifyPolicyBundle,
} from "./policy-bundle.js";

/**
 * A cache shared by more isolates than one. Deliberately two methods, so a KV
 * namespace, a Durable Object stub, or `caches.default` all fit behind it.
 *
 *     store: {
 *       get: (key) => env.POLICY.get(key),
 *       put: (key, envelope, ttl) =>
 *         env.POLICY.put(key, envelope, { expirationTtl: Math.max(60, ttl) }),
 *     }
 */
export interface PolicyStore {
  get(key: string): Promise<string | null | undefined>;
  put(key: string, envelope: string, ttlSeconds: number): Promise<unknown>;
}

/** What happened on a policy load. Versions and reasons only — never a value. */
export interface PolicyEvent {
  kind: "loaded" | "not_modified" | "refresh_failed" | "unusable";
  agent: string;
  from?: "store" | "api";
  policyVersion?: number;
  expiresAt?: number;
  /** Present on `refresh_failed` and `unusable`. */
  message?: string;
}

export interface PolicySourceOptions {
  /**
   * **The trust anchor.** RFC 7638 thumbprints of the keys whose signatures
   * this deployment accepts, from your own config — a `wrangler.jsonc` var, a
   * secret, a constant in this file. The one input that must not come from the
   * API, since the API is what it is checking.
   */
  signers: string[];
  /** The agent identity this deployment is: an id or a slug. */
  agent: string;
  /** Optional org id, checked against the bundle's claim as a second binding. */
  org?: string;
  /**
   * The local bound on server policy: host → the secret names ever permissible
   * here. A bundle that exceeds it is refused **wholesale** rather than
   * narrowed, because a policy that means less than what was published is a
   * policy nobody authored.
   */
  ceiling?: PolicyCeiling;
  /** How long a verified bundle is reused in this isolate (default 300s). */
  refreshSeconds?: number;
  /** A cache shared across isolates, in front of the API. */
  store?: PolicyStore;
  /** Key used with {@link store}. Defaults to `seekrit:policy:<agent>`. */
  storeKey?: string;
  /**
   * Hand a background refresh to the runtime — `(p) => ctx.waitUntil(p)`.
   * Without it, the request that finds the bundle stale waits for the refresh.
   */
  waitUntil?: (promise: Promise<unknown>) => void;
  /** `skt_…` service token used to fetch the bundle. Defaults to `$SEEKRIT_TOKEN`. */
  token?: string;
  /** API base URL. Defaults to `$SEEKRIT_API_URL`. */
  apiUrl?: string;
  /** The fetch used to reach the API. */
  fetch?: typeof globalThis.fetch;
  /**
   * Replace the default `GET /v1/agents/:agent/policy` entirely — return an
   * `ap1.` envelope, or `null` when nothing changed. Use this to read a bundle
   * you push from your own control plane instead of pulling it.
   */
  fetchBundle?: (etag?: string) => Promise<{ envelope: string | null; etag?: string }>;
  /** Notified on every load, 304, and failure. */
  onPolicy?: (event: PolicyEvent) => void;
}

/** A verified bundle and the rules it carries. */
export interface LoadedPolicy {
  bundle: PolicyBundle;
  rules: PolicyBundleRule[];
}

/** Resolves the rules in force right now, or throws if there are none to trust. */
export interface PolicySource {
  current(): Promise<LoadedPolicy>;
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
    return undefined;
  }
}

/**
 * Build the live policy for one agent identity.
 *
 * Every path through this is fail-closed: no bundle, an unverifiable bundle, a
 * bundle for someone else, an expired bundle, or one that exceeds the ceiling
 * all end as a thrown {@link SeekritPolicyError}. There is no "carry on with
 * the last good rules" — that is exactly the behaviour a revocation is trying
 * to stop.
 */
export function createPolicySource(options: PolicySourceOptions): PolicySource {
  if (options.signers.length === 0) {
    throw new SeekritError(
      "a policy source needs pinned signers: without them the API decides where your credentials go",
    );
  }
  const refreshMs = Math.max(0, options.refreshSeconds ?? 300) * 1000;
  const storeKey = options.storeKey ?? `seekrit:policy:${options.agent}`;

  let current: LoadedPolicy | undefined;
  let refreshAt = 0;
  let etag: string | undefined;
  let inflight: Promise<LoadedPolicy> | undefined;

  function send(): typeof globalThis.fetch {
    const impl = options.fetch ?? globalThis.fetch;
    if (typeof impl !== "function") {
      throw new SeekritError("no global fetch available; pass { fetch } explicitly");
    }
    return impl.bind(globalThis);
  }

  /** `GET /v1/agents/:agent/policy` — the same endpoint the proxy reads. */
  async function fetchFromApi(): Promise<{ envelope: string | null; etag?: string }> {
    if (options.fetchBundle) return options.fetchBundle(etag);
    const token = options.token ?? readEnv("SEEKRIT_TOKEN");
    if (!token) {
      throw new SeekritError("no service token: pass { token } or set SEEKRIT_TOKEN");
    }
    const base = (options.apiUrl ?? readEnv("SEEKRIT_API_URL") ?? "https://api.seekrit.dev").replace(
      /\/+$/,
      "",
    );
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
      accept: "application/json",
    };
    // Conditional on purpose: a short refresh interval is affordable when the
    // steady state costs one 304.
    if (etag) headers["if-none-match"] = etag;
    const response = await send()(
      `${base}/v1/agents/${encodeURIComponent(options.agent)}/policy`,
      { headers },
    );
    if (response.status === 304) return { envelope: null, etag };
    if (!response.ok) {
      throw new SeekritPolicyError(`could not fetch agent policy: HTTP ${response.status}`);
    }
    const body = (await response.json()) as { bundle?: string };
    if (!body.bundle) {
      throw new SeekritPolicyError(
        "policy response carries no bundle — has a policy been published for this agent?",
      );
    }
    return { envelope: body.bundle, etag: response.headers.get("etag") ?? undefined };
  }

  /** Verify, bind, bound. The only way a bundle becomes `current`. */
  async function accept(envelope: string, from: "store" | "api"): Promise<LoadedPolicy> {
    const bundle = await verifyPolicyBundle(envelope, options.signers);
    checkPolicyBundleContext(bundle, { org: options.org, agent: options.agent });
    if (options.ceiling) checkPolicyCeiling(bundle.rules, options.ceiling);
    options.onPolicy?.({
      kind: "loaded",
      agent: options.agent,
      from,
      policyVersion: bundle.policy_version,
      expiresAt: bundle.expires_at,
    });
    return { bundle, rules: bundle.rules };
  }

  async function refresh(): Promise<LoadedPolicy> {
    // The shared cache first: it is what keeps a swarm of isolates from each
    // asking the API on its own schedule.
    if (options.store) {
      const cached = await Promise.resolve(options.store.get(storeKey)).catch(() => null);
      if (cached) {
        try {
          const loaded = await accept(cached, "store");
          current = loaded;
          refreshAt = Date.now() + refreshMs;
          return loaded;
        } catch {
          // A cached bundle that no longer checks out (expired, or its signer
          // was rotated out) is not fatal — fall through and ask the API.
        }
      }
    }

    const fetched = await fetchFromApi();
    if (fetched.etag) etag = fetched.etag;
    if (fetched.envelope === null) {
      // 304: what we hold is still the published policy.
      if (!current) {
        throw new SeekritPolicyError("policy unchanged, but this isolate holds no bundle");
      }
      options.onPolicy?.({
        kind: "not_modified",
        agent: options.agent,
        policyVersion: current.bundle.policy_version,
      });
      refreshAt = Date.now() + refreshMs;
      return current;
    }

    const loaded = await accept(fetched.envelope, "api");
    current = loaded;
    refreshAt = Date.now() + refreshMs;
    if (options.store) {
      const remaining = loaded.bundle.expires_at - Math.floor(Date.now() / 1000);
      const ttl = Math.max(60, Math.min(Math.ceil(refreshMs / 1000), remaining));
      // A store that is unreachable is a performance problem, not a correctness
      // one: the bundle in hand is already verified.
      await Promise.resolve(options.store.put(storeKey, fetched.envelope, ttl)).catch(() => {});
    }
    return loaded;
  }

  /** One refresh at a time per isolate, however many requests arrive at once. */
  function refreshOnce(): Promise<LoadedPolicy> {
    inflight ??= refresh().finally(() => {
      inflight = undefined;
    });
    return inflight;
  }

  function usable(loaded: LoadedPolicy | undefined): loaded is LoadedPolicy {
    if (!loaded) return false;
    return Math.floor(Date.now() / 1000) < loaded.bundle.expires_at;
  }

  return {
    async current(): Promise<LoadedPolicy> {
      const held = current;
      if (usable(held) && Date.now() < refreshAt) return held;

      if (usable(held)) {
        // Due for a refresh, but what we hold is still valid. Only background it
        // when the runtime will keep the work alive.
        if (options.waitUntil) {
          options.waitUntil(
            refreshOnce().catch((error: unknown) => {
              options.onPolicy?.({
                kind: "refresh_failed",
                agent: options.agent,
                message: error instanceof Error ? error.message : String(error),
              });
            }),
          );
          return held;
        }
        try {
          return await refreshOnce();
        } catch (error) {
          options.onPolicy?.({
            kind: "refresh_failed",
            agent: options.agent,
            message: error instanceof Error ? error.message : String(error),
          });
          return held; // still inside its own expiry, so still authorised
        }
      }

      // Nothing usable in hand: this one has to wait, and has to fail closed.
      try {
        return await refreshOnce();
      } catch (error) {
        current = undefined;
        const message = error instanceof Error ? error.message : String(error);
        options.onPolicy?.({ kind: "unusable", agent: options.agent, message });
        throw error instanceof SeekritPolicyError ? error : new SeekritPolicyError(message);
      }
    },
  };
}
