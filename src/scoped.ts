/**
 * Per-scope `fetch` instances, LRU-bounded — shared by every adapter that has
 * to serve more than one tenant from one process.
 *
 * This exists for one reason: {@link seekritFetch} caches a resolved set inside
 * its own closure, so building a fresh one per request would resolve on every
 * request and quietly undo the TTL. One instance per scope keeps the cache while
 * still isolating tenants from each other.
 */
import { seekritFetch, type SeekritFetchOptions, type SeekritFetchScope } from "./fetch.js";

/** A stable key for a set of group overrides, so two equal sets share a resolve. */
export function withKey(overrides: Record<string, string> | undefined): string {
  return overrides ? JSON.stringify(Object.entries(overrides).sort()) : "";
}

/** A stable key for a scope, so two equal scopes share one resolve. */
export function scopeKey(scope: SeekritFetchScope | undefined): string {
  if (!scope) return "";
  const allowPart = scope.allow ? JSON.stringify([...scope.allow].sort()) : "";
  return `${withKey(scope.with)}|${allowPart}`;
}

/** Options every scoped `fetch` shares — the scope itself is per request. */
export type SharedFetchOptions = Omit<SeekritFetchOptions, "scope">;

/**
 * A `fetch` per distinct scope, least-recently-used beyond `maxScopes` dropped
 * and resolved again on next use.
 */
export function scopedFetch(options: SharedFetchOptions, maxScopes = 64) {
  const cache = new Map<string, typeof globalThis.fetch>();
  const limit = Math.max(1, maxScopes);
  return (scope: SeekritFetchScope | undefined): typeof globalThis.fetch => {
    const key = scopeKey(scope);
    const hit = cache.get(key);
    if (hit) {
      cache.delete(key); // re-insert so iteration order is least-recent-first
      cache.set(key, hit);
      return hit;
    }
    const created = seekritFetch({ ...options, scope: () => scope });
    cache.set(key, created);
    if (cache.size > limit) {
      const oldest = cache.keys().next();
      if (!oldest.done) cache.delete(oldest.value);
    }
    return created;
  };
}
