/**
 * Mastra adapter — per-request credentials, without a per-request resolve.
 *
 *     import { createOpenAI } from "@ai-sdk/openai";
 *     import { Agent } from "@mastra/core/agent";
 *     import { seekritModel } from "@seekrit/sdk/mastra";
 *
 *     export const support = new Agent({
 *       id: "support",
 *       name: "Support Agent",
 *       instructions: "You are a helpful support agent",
 *       model: seekritModel(
 *         ({ apiKey, fetch }) => createOpenAI({ apiKey, fetch })("gpt-5.6-sol"),
 *         {
 *           secret: "OPENAI_API_KEY",
 *           allow: { "api.openai.com": ["OPENAI_API_KEY"] },
 *           scope: (rc) => ({ with: { tenants: String(rc.get("tenant")) } }),
 *         },
 *       ),
 *     });
 *
 * Mastra types `model` as `DynamicArgument<MastraModelConfig>` — either a model
 * or a function of `{ requestContext }` — and accepts an AI SDK provider
 * instance anywhere it accepts a `"provider/model"` string. Those two facts are
 * the whole integration: {@link seekritModel} returns the function form, and
 * hands your builder an `apiKey` placeholder and a `fetch` already scoped to
 * this request.
 *
 * Nothing here imports `@mastra/core`. Every Mastra shape this file touches is
 * declared structurally below, so the adapter cannot break on a Mastra version
 * bump and `@seekrit/sdk` stays dependency-free.
 *
 * **Why not the object model form.** Mastra's `OpenAICompatibleConfig` takes
 * `id`, `url`, `apiKey` and `headers` — but no `fetch`, so it cannot carry the
 * substitution. Pointing its `url` at the [proxy](https://seekrit.dev/docs/guides/agent-proxy)
 * is the other way to hold a placeholder there, and a stronger one.
 */
import { seekritFetch, type SeekritFetchOptions, type SeekritFetchScope } from "./fetch.js";
import { placeholder } from "./substitute.js";

/** The one method this adapter needs from Mastra's `RequestContext`. */
export interface RequestContextLike {
  get(key: string): unknown;
}

/** The one method the middleware needs to write a request context. */
export interface RequestContextWritable {
  set(key: string, value: unknown): void;
  setRaw?(key: string, value: unknown): void;
}

/** What Mastra passes to a `DynamicArgument` function. `mastra` is ignored. */
export interface DynamicArgumentContext {
  requestContext: RequestContextLike;
}

/** What {@link seekritModel} hands your builder, once per request. */
export interface SeekritModelCredentials {
  /** `{{seekrit:NAME}}` for the configured `secret`. Pass it as the API key. */
  apiKey: string;
  /** A `fetch` that substitutes, scoped to this request. Reused across requests
   *  with the same scope, so the resolve is cached rather than repeated. */
  fetch: typeof globalThis.fetch;
  /** The scope this request resolved under, for logging. Never a value. */
  scope: SeekritFetchScope | undefined;
}

type SharedFetchOptions = Omit<SeekritFetchOptions, "scope">;

export interface SeekritModelOptions extends SharedFetchOptions {
  /** The secret whose placeholder becomes `apiKey`. */
  secret: string;
  /**
   * Derive this request's scope from the request context — which slice to
   * resolve (`with`) and, optionally, a narrowed allowlist. Omit for a
   * single-tenant agent.
   *
   * If this returns `with` overrides, credentials come from `token` /
   * `$SEEKRIT_TOKEN` (a scoped client is built per tenant) or from `client`
   * passed as a **function** of those overrides. A single `client` object cannot
   * be re-scoped, and saying so is why that combination throws rather than
   * resolving the wrong tenant.
   */
  scope?: (requestContext: RequestContextLike) => SeekritFetchScope | undefined;
  /**
   * How many distinct scopes to keep a `fetch` (and therefore a resolved set)
   * for. Least-recently-used beyond this is dropped and resolved again on next
   * use. Default 64 — raise it for a fleet with more concurrent tenants than
   * that, lower it to hold less in memory.
   */
  maxScopes?: number;
}

/** A stable key for a scope, so two equal scopes share one resolve. */
function scopeKey(scope: SeekritFetchScope | undefined): string {
  if (!scope) return "";
  const withPart = scope.with ? JSON.stringify(Object.entries(scope.with).sort()) : "";
  const allowPart = scope.allow ? JSON.stringify([...scope.allow].sort()) : "";
  return `${withPart}|${allowPart}`;
}

/**
 * A `fetch` per distinct scope, LRU-bounded.
 *
 * This exists for one reason: `seekritFetch` caches a resolved set inside its
 * own closure, so building a fresh one per request would resolve on every
 * request and quietly undo the TTL. One instance per scope keeps the cache
 * while still isolating tenants from each other.
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

/**
 * Build a Mastra dynamic `model` that resolves credentials per request.
 *
 * `build` runs once per request and receives the placeholder and the scoped
 * `fetch`; return whatever model your provider makes. It runs per request on
 * purpose — the `fetch` is shared, but your builder may want to vary the model
 * id, temperature, or provider by tenant too.
 */
export function seekritModel<TModel>(
  build: (credentials: SeekritModelCredentials) => TModel,
  options: SeekritModelOptions,
): (context: DynamicArgumentContext) => TModel {
  const { secret, scope: deriveScope, maxScopes, ...fetchOptions } = options;
  const apiKey = placeholder(secret);
  const fetchFor = scopedFetch(fetchOptions, maxScopes);

  return ({ requestContext }: DynamicArgumentContext): TModel => {
    const scope = deriveScope?.(requestContext);
    return build({ apiKey, fetch: fetchFor(scope), scope });
  };
}

/** What a tool's execution options look like, as far as this adapter cares. */
export interface ToolExecutionContextLike {
  requestContext?: RequestContextLike;
}

export interface SeekritToolFetchOptions extends SharedFetchOptions {
  /**
   * Narrow this tool's allowlist to these names. Intersected with `allow` /
   * `rules`, never widening — so a tool that calls Stripe can be given
   * `["STRIPE_SECRET_KEY"]` and nothing else it could reach.
   */
  only?: string[];
  scope?: (requestContext: RequestContextLike) => SeekritFetchScope | undefined;
  maxScopes?: number;
  /** Label for `onInject`, e.g. the tool id. Never a value. */
  label?: string;
}

/**
 * A `fetch` for a Mastra tool's own outbound calls, scoped to the request the
 * tool is running in and narrowed to the secrets that tool may inject.
 *
 *     export const refund = createTool({
 *       id: "refund",
 *       description: "Refund a charge",
 *       inputSchema: z.object({ chargeId: z.string() }),
 *       execute: async ({ chargeId }, context) => {
 *         const fetch = refundFetch(context);
 *         return fetch("https://api.stripe.com/v1/refunds", {
 *           method: "POST",
 *           headers: { authorization: "Bearer {{seekrit:STRIPE_SECRET_KEY}}" },
 *           body: new URLSearchParams({ charge: chargeId }),
 *         });
 *       },
 *     });
 *
 * where `refundFetch = seekritToolFetch({ allow: {...}, only: ["STRIPE_SECRET_KEY"] })`
 * is built once at module scope. Build it there rather than inside `execute`, or
 * every tool call resolves again.
 */
export function seekritToolFetch(options: SeekritToolFetchOptions) {
  const { only, scope: deriveScope, maxScopes, label, ...fetchOptions } = options;
  const fetchFor = scopedFetch(fetchOptions, maxScopes);
  return (context?: ToolExecutionContextLike): typeof globalThis.fetch => {
    const requestContext = context?.requestContext;
    const derived = requestContext ? deriveScope?.(requestContext) : undefined;
    // `only` always applies, request context or not: a tool's ceiling is a
    // property of the tool, not of who called it.
    if (!only) return fetchFor(derived);
    return fetchFor({ ...derived, allow: only, label } as SeekritFetchScope);
  };
}

/**
 * Mastra `server.middleware` that lifts a request header into the request
 * context, so `scope` has something to read.
 *
 *     export const mastra = new Mastra({
 *       agents: { support },
 *       server: { middleware: [seekritRequestContext({ header: "x-tenant" })] },
 *     });
 *
 * The header name defaults to `x-seekrit-tenant` and the context key to
 * `tenant`. A request with no such header sets nothing, which leaves `scope`
 * returning `undefined` and the agent resolving its token's own environment.
 *
 * **This trusts the header.** It is the right shape behind your own
 * authenticated edge, and the wrong one facing the internet — there, set the
 * key from your verified session in your own middleware instead. A caller who
 * can pick the header can pick the tenant.
 */
export function seekritRequestContext(options: { header?: string; key?: string } = {}) {
  const header = options.header ?? "x-seekrit-tenant";
  const key = options.key ?? "tenant";
  return async (
    context: {
      req: { header(name: string): string | undefined };
      get(name: "requestContext"): RequestContextWritable | undefined;
    },
    next: () => Promise<void>,
  ): Promise<void> => {
    const value = context.req.header(header);
    const requestContext = context.get("requestContext");
    if (value && requestContext) {
      // setRaw when available: the key is usually not in requestContextSchema.
      if (requestContext.setRaw) requestContext.setRaw(key, value);
      else requestContext.set(key, value);
    }
    await next();
  };
}

export { placeholder } from "./substitute.js";
export type { SeekritFetchScope } from "./fetch.js";
