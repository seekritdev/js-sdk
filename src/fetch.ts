/**
 * `seekritFetch` — hold a placeholder, not a credential.
 *
 *     import { createOpenAI } from "@ai-sdk/openai";
 *     import { seekritFetch } from "@seekrit/sdk/fetch";
 *
 *     const openai = createOpenAI({
 *       apiKey: "{{seekrit:OPENAI_API_KEY}}",
 *       fetch: seekritFetch({ allow: { "api.openai.com": ["OPENAI_API_KEY"] } }),
 *     });
 *
 * The key never exists in your source, your `.env`, or `process.env`. It is
 * resolved and decrypted here, substituted into the outbound request, and
 * nowhere else — so it cannot reach model context, a tool result, or a trace
 * exporter, which is where credentials actually leak in an agent.
 *
 * **What this is not.** It runs in your process, so it is not the trust boundary
 * `apps/proxy` is: code in this process can read the value or replace this
 * function. It is the rung of the ladder above environment variables and below
 * the proxy. Reach for the proxy when the code holding the placeholder is code
 * you do not trust.
 *
 * Only requests that *carry a placeholder* are gated. A request with no
 * placeholder passes straight through — this is a credential shim, not an egress
 * firewall, and silently blocking unrelated traffic would be a worse lie than
 * not blocking it.
 */
import { Seekrit } from "./client.js";
import { SeekritError, SeekritSubstitutionError } from "./errors.js";
import { type AllowRule, evaluate, rulesFromAllow } from "./policy.js";
import { hasPlaceholder, type Lookup, substitute } from "./substitute.js";

/** Per-request narrowing, returned by {@link SeekritFetchOptions.scope}. */
export interface SeekritFetchScope {
  /** `{ groupSlug: envSlug }` overrides — resolve a different slice per request. */
  with?: Record<string, string>;
  /**
   * Narrow the allowlist for this request to these names. Intersected with the
   * static rules, never widening them. This is how per-tool scoping works: the
   * agent's rules say what the *process* may inject, the scope says what *this
   * tool call* may.
   */
  allow?: string[];
}

export interface SeekritFetchOptions {
  /** Shorthand: `{ "api.openai.com": ["OPENAI_API_KEY"] }`, any method or path. */
  allow?: Record<string, string[]>;
  /**
   * Full rules, host by host. This is the wire shape of a signed `ap1.` bundle's
   * `rules`, so a verified bundle's array can be passed straight in.
   */
  rules?: AllowRule[];
  /** `skt_…` service token. Defaults to `$SEEKRIT_TOKEN`. */
  token?: string;
  /** API base URL. Defaults to `$SEEKRIT_API_URL`. */
  apiUrl?: string;
  /** A pre-built client, used when no per-request `with` scope is in play. */
  client?: Seekrit;
  /** Called once per request to narrow the resolve and the allowlist. */
  scope?: () => SeekritFetchScope | undefined;
  /**
   * How long a resolved set may be reused, per scope (default 60). `0` resolves
   * on every request that carries a placeholder — correct, and one extra round
   * trip per model call. Values live in memory only.
   */
  ttlSeconds?: number;
  /**
   * Also scan the request body (default `true`). String, `URLSearchParams` and
   * byte bodies are scanned; a streamed body never is, because buffering it
   * here would break streaming uploads.
   */
  body?: boolean;
  /** The fetch to send with. Defaults to the global at construction time. */
  fetch?: typeof globalThis.fetch;
  /**
   * How a refusal reaches the caller (default `"respond"`).
   *
   * `"respond"` answers with the same **403** the proxy answers with, body and
   * all, and never sends the request. That is deliberate: a provider SDK wraps
   * anything its `fetch` throws into its own opaque connection error *and
   * retries it*, so a denied placeholder would surface as "Connection error"
   * after six attempts instead of naming the secret. A 403 is terminal in every
   * provider SDK, and it means swapping this shim for the proxy does not change
   * your error handling.
   *
   * `"throw"` raises {@link SeekritSubstitutionError} instead — right when you
   * call this function yourself rather than handing it to an SDK.
   *
   * A failure to *resolve* (the seekrit API being unreachable) always throws
   * either way: that one is genuinely transient and worth a retry.
   */
  refusal?: "respond" | "throw";
  /** Notified on every refusal, whichever way it surfaces. Names only. */
  onRefuse?: (error: SeekritSubstitutionError) => void;
  /** Notified after a successful substitution. Names only — never values. */
  onInject?: (event: { host: string; method: string; path: string; names: string[] }) => void;
}

type BodyInit_ = RequestInit["body"];

/** Mirrors `Reject::into_response` in `apps/proxy/src/proxy.rs`, verbatim. */
function refusalBody(error: SeekritSubstitutionError): string {
  return error.code === "denied"
    ? `placeholder {{seekrit:${error.secretName}}} is not allowed toward this upstream`
    : `placeholder {{seekrit:${error.secretName}}} references a secret that is not available`;
}

function refusalResponse(error: SeekritSubstitutionError): Response {
  return new Response(refusalBody(error), {
    status: 403,
    statusText: "Forbidden",
    headers: {
      "content-type": "text/plain; charset=utf-8",
      // Machine-checkable, so a caller can tell our refusal from an upstream 403.
      "x-seekrit-refusal": error.code,
      "x-seekrit-secret": error.secretName,
    },
  });
}

/** A body we can scan without consuming a stream. */
function readableBody(body: BodyInit_): string | undefined {
  if (typeof body === "string") return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body));
  return undefined;
}

function reencodeBody(original: BodyInit_, text: string): BodyInit_ {
  if (original instanceof URLSearchParams) return new URLSearchParams(text);
  if (original instanceof Uint8Array || original instanceof ArrayBuffer) {
    return new TextEncoder().encode(text);
  }
  return text;
}

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function isRequestLike(input: RequestInfo | URL): input is Request {
  return typeof input === "object" && input !== null && "url" in input && "headers" in input;
}

/**
 * Build a fetch that substitutes `{{seekrit:NAME}}` placeholders in the URL,
 * the headers, and (by default) the body of every outbound request.
 */
export function seekritFetch(options: SeekritFetchOptions = {}): typeof globalThis.fetch {
  const staticRules: AllowRule[] = [
    ...(options.rules ?? []),
    ...(options.allow ? rulesFromAllow(options.allow) : []),
  ];
  if (staticRules.length === 0) {
    throw new SeekritError("seekritFetch needs an allowlist: pass { allow } or { rules }");
  }

  const ttlMs = Math.max(0, options.ttlSeconds ?? 60) * 1000;
  const scanBody = options.body ?? true;
  const refusalMode = options.refusal ?? "respond";
  // Captured now, so installing this function as the global fetch cannot make
  // the resolve call recurse back into it.
  const plainFetch = options.fetch ?? globalThis.fetch;
  if (typeof plainFetch !== "function") {
    throw new SeekritError("no global fetch available; pass { fetch } explicitly");
  }
  const send = plainFetch.bind(globalThis);

  const cache = new Map<string, { expires: number; values: Promise<Record<string, string>> }>();

  function resolveFor(scope: SeekritFetchScope | undefined): Promise<Record<string, string>> {
    const withOverrides = scope?.with;
    const key = withOverrides ? JSON.stringify(Object.entries(withOverrides).sort()) : "";
    const hit = cache.get(key);
    const now = Date.now();
    if (hit && hit.expires > now) return hit.values;

    const client =
      !withOverrides && options.client
        ? options.client
        : new Seekrit({
            token: options.token,
            apiUrl: options.apiUrl,
            with: withOverrides,
            fetch: send,
          });
    const values = client.resolve().catch((error: unknown) => {
      cache.delete(key); // never cache a failure
      throw error;
    });
    if (ttlMs > 0) cache.set(key, { expires: now + ttlMs, values });
    return values;
  }

  /** Substitute and send. Throws {@link SeekritSubstitutionError} on a refusal. */
  async function inject(
    input: RequestInfo | URL,
    init: RequestInit | undefined,
    urlString: string,
    headers: Headers,
    bodyText: string | undefined,
  ): Promise<Response> {
    const parsed = new URL(urlString);
    const method = (init?.method ?? (isRequestLike(input) ? input.method : "GET")).toUpperCase();
    const scope = options.scope?.();
    const rules = scope?.allow ? narrow(staticRules, scope.allow) : staticRules;
    const values = await resolveFor(scope);

    const injected = new Set<string>();
    const lookup = (name: string): Lookup => {
      const verdict = evaluate(rules, {
        host: parsed.hostname,
        method,
        path: parsed.pathname,
        secret: name,
      });
      if (verdict.decision !== "allow") return { kind: "denied", reason: verdict.decision };
      const value = values[name];
      if (value === undefined) return { kind: "unknown" };
      injected.add(name);
      return { kind: "value", value };
    };

    const rewrittenUrl = substitute(urlString, lookup).text;
    if (rewrittenUrl !== urlString && isRequestLike(input)) {
      throw new SeekritError(
        "a placeholder in the URL of a Request object cannot be substituted; pass the URL as a string",
      );
    }

    const nextHeaders = new Headers();
    headers.forEach((value, name) => {
      nextHeaders.set(name, substitute(value, lookup).text);
    });

    const bodyInit = init?.body;
    let nextBody = bodyInit;
    if (bodyText !== undefined) {
      const rewritten = substitute(bodyText, lookup).text;
      if (rewritten !== bodyText) nextBody = reencodeBody(bodyInit, rewritten);
    }

    if (injected.size > 0) {
      options.onInject?.({
        host: parsed.hostname,
        method,
        path: parsed.pathname,
        names: [...injected].sort(),
      });
    }

    if (isRequestLike(input)) {
      const requestInit: RequestInit = { ...init, headers: nextHeaders };
      if (nextBody !== bodyInit) requestInit.body = nextBody;
      return send(new Request(input, requestInit));
    }
    return send(rewrittenUrl, { ...init, headers: nextHeaders, body: nextBody });
  }

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const urlString = urlOf(input);
    const headers = new Headers(init?.headers ?? (isRequestLike(input) ? input.headers : undefined));
    const bodyText = scanBody ? readableBody(init?.body) : undefined;

    let touched = hasPlaceholder(urlString);
    if (!touched) {
      headers.forEach((value) => {
        if (!touched && hasPlaceholder(value)) touched = true;
      });
    }
    if (!touched && bodyText !== undefined) touched = hasPlaceholder(bodyText);
    // No placeholder: not our request. Pass it through exactly as given — this
    // is a credential shim, not an egress firewall.
    if (!touched) return send(input, init);

    try {
      return await inject(input, init, urlString, headers, bodyText);
    } catch (error) {
      if (error instanceof SeekritSubstitutionError) {
        options.onRefuse?.(error);
        if (refusalMode === "respond") return refusalResponse(error);
      }
      throw error;
    }
  };
}

/**
 * Intersect every rule's `allow` with `names` — narrowing only. A name the
 * static rules never permitted cannot be introduced by a scope.
 */
function narrow(rules: AllowRule[], names: string[]): AllowRule[] {
  const wanted = new Set(names);
  return rules.map((rule) => ({
    ...rule,
    allow: (rule.allow ?? []).filter((name) => wanted.has(name)),
  }));
}

// Re-exported for callers building their own injection path (a custom transport,
// a test double, or an allowlist derived from a verified policy bundle).
export {
  hasPlaceholder,
  substitute,
  type Lookup,
  type SubstitutionOutcome,
} from "./substitute.js";
export {
  evaluate,
  matchPath,
  rulesFromAllow,
  type AllowRule,
  type PolicyDecision,
  type PolicyQuery,
  type PolicyVerdict,
} from "./policy.js";
export { SeekritSubstitutionError, type SubstitutionErrorCode } from "./errors.js";
