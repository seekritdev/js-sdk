/**
 * `@seekrit/sdk/route` — the client holds a placeholder; this handler holds the
 * key.
 *
 *     // app/api/openai/[...path]/route.ts
 *     import { seekritRoute } from "@seekrit/sdk/route";
 *     import { auth } from "@/auth";
 *
 *     export const { GET, POST } = seekritRoute({
 *       upstream: "https://api.openai.com",
 *       allow: { "api.openai.com": ["OPENAI_API_KEY"] },
 *       authorize: async (request) => (await auth(request)) !== null,
 *     });
 *
 * and on the client:
 *
 *     const openai = createOpenAI({
 *       baseURL: "/api/openai/v1",
 *       apiKey: "{{seekrit:OPENAI_API_KEY}}",
 *     });
 *
 * This is [`apps/proxy`](https://seekrit.dev/docs/guides/agent-proxy) shaped as a
 * web `Request` → `Response` handler: same `{{seekrit:NAME}}` syntax, same
 * default-deny allowlist, same 403. It runs on Next.js route handlers, Remix and
 * React Router actions, Hono, Nitro — anything that hands you a `Request`.
 *
 * **Three ways this is weaker than the proxy**, all worth knowing before you
 * reach for it:
 *
 *   1. It is reachable from the internet, on your own origin, under your own
 *      cookies. {@link SeekritRouteOptions.authorize} is therefore required and
 *      has no default — an unauthenticated handler here is an open credential
 *      proxy, and a same-origin one at that.
 *   2. It runs in your app's process, so app code can read the resolved value.
 *   3. The allowlist bounds where the key can go, not what your own client code
 *      does with the response.
 *
 * What it does buy: the key is never in the client bundle, never in
 * `localStorage`, never in a network tab, and a browser that is compromised
 * gains the ability to *use* the credential through your authenticated origin,
 * not to *take* it.
 *
 * **The allowlist gates the operation, not just the placeholder.** The
 * in-process shim only consults policy for requests that carry a placeholder,
 * because it is a credential shim and not an egress firewall. A handler on the
 * public internet cannot afford that reading: without an operation-level check,
 * an authorized user could drive any path or method on the upstream simply by
 * omitting the placeholder. So every request is evaluated against
 * `methods`/`paths` first, placeholder or not.
 */
import { SeekritError } from "./errors.js";
import type { SeekritFetchOptions, SeekritFetchScope } from "./fetch.js";
import { type AllowRule, evaluate, type PolicyVerdict, rulesFromAllow } from "./policy.js";
import { scopedFetch } from "./scoped.js";
import { assertServerOnly } from "./server-only.js";
import { hasPlaceholder } from "./substitute.js";

assertServerOnly("route");

/** What a framework hands a handler after the `Request`. Only `params` is read. */
export interface RouteContext {
  params?: Record<string, string | string[]> | Promise<Record<string, string | string[]>>;
}

export type RouteHandler = (request: Request, context?: RouteContext) => Promise<Response>;

/** One handler per method, all the same function — export the ones you need. */
export interface SeekritRouteHandlers {
  GET: RouteHandler;
  HEAD: RouteHandler;
  POST: RouteHandler;
  PUT: RouteHandler;
  PATCH: RouteHandler;
  DELETE: RouteHandler;
  OPTIONS: RouteHandler;
  /** The handler itself, for a framework that wants one function. */
  handle: RouteHandler;
}

export interface SeekritRouteOptions extends Omit<SeekritFetchOptions, "scope" | "refusal"> {
  /**
   * Where the request goes. A base URL rewrites this route's tail onto it
   * (`/api/openai/v1/chat` → `https://api.openai.com/v1/chat`), which is the
   * `[[route]]` mode of the proxy.
   *
   * Pass a function for anything else — reading a target out of the request,
   * choosing an upstream per tenant, or refusing. Returning `undefined` is a
   * 404, and the returned URL is still subject to the allowlist.
   */
  upstream: string | ((request: Request, path: string) => string | undefined | Promise<string | undefined>);
  /**
   * Whether this request may use the credentials. **Required**: a handler that
   * injects a key for anyone who can reach the URL is an open credential proxy.
   *
   * Check your own session here — the same check the rest of your app makes.
   * Returning `false` answers 401 and sends nothing upstream.
   *
   * Do not read the request body here: this handler reads it afterwards to
   * substitute into it, and a `Request` body can only be consumed once. Clone
   * first if you must (`request.clone().json()`).
   */
  authorize: (request: Request) => boolean | Promise<boolean>;
  /**
   * Narrow the resolve and the allowlist per request (e.g. per tenant).
   * Same rule as `authorize`: do not consume the body.
   */
  scope?: (request: Request) => SeekritFetchScope | undefined | Promise<SeekritFetchScope | undefined>;
  /**
   * The route's own prefix, stripped from the path before it is joined onto
   * `upstream` — `"/api/openai"`. Only needed when the framework does not hand
   * this handler a catch-all `params`, which is where the tail normally comes
   * from.
   */
  basePath?: string;
  /**
   * Rewrite the headers that go upstream, after the unsafe ones are dropped.
   * The default drops hop-by-hop headers, `cookie`, the forwarding and origin
   * headers, and any `authorization` that is *not* carrying a placeholder.
   */
  headers?: (headers: Headers, request: Request) => Headers;
  /** Refuse a body larger than this, in bytes (default 1 MiB). `0` disables the cap. */
  maxBodyBytes?: number;
  /** Distinct scopes to keep a resolved set for (default 64). */
  maxScopes?: number;
}

/**
 * Never forwarded upstream.
 *
 * `cookie` is the important one: the browser attaches your session to a
 * same-origin request automatically, and forwarding it hands your session to a
 * third party. `accept-encoding` is dropped so the runtime negotiates and
 * decodes compression itself — forwarding it can leave a decoded body labelled
 * with the original `content-encoding`.
 */
const DROP_REQUEST_HEADERS = new Set([
  "accept-encoding",
  "connection",
  "content-length",
  "cookie",
  "expect",
  "host",
  "keep-alive",
  "origin",
  "proxy-authorization",
  "referer",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
]);

/**
 * Never relayed back to the browser.
 *
 * `set-cookie` matters most: this handler is same-origin, so an upstream's
 * cookie would be set on *your* domain. The encoding and length headers go
 * because the body may have been decompressed on the way in.
 */
const DROP_RESPONSE_HEADERS = new Set([
  "connection",
  "content-encoding",
  "content-length",
  "keep-alive",
  "set-cookie",
  "transfer-encoding",
]);

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

function textResponse(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", ...headers },
  });
}

/** Mirrors the shim's refusal shape, so a client cannot tell which one refused. */
function operationRefusal(verdict: PolicyVerdict): Response {
  return textResponse(403, `this request is not allowed toward this upstream (${verdict.decision})`, {
    "x-seekrit-refusal": verdict.decision,
  });
}

/**
 * The tail of the route: everything after this handler's own prefix.
 *
 * A catch-all `params` is the reliable source and is preferred — Next.js 15
 * makes it a promise, older versions an object, and the segment name is the
 * caller's choice, so the first array-valued entry is taken rather than a
 * hardcoded key. `basePath` is the fallback for frameworks that pass no params.
 */
async function pathOf(
  request: Request,
  context: RouteContext | undefined,
  basePath: string | undefined,
): Promise<string> {
  const params = await context?.params;
  if (params) {
    for (const value of Object.values(params)) {
      if (Array.isArray(value)) return `/${value.map(encodeSegment).join("/")}`;
    }
  }
  const { pathname } = new URL(request.url);
  if (basePath) {
    const prefix = basePath.replace(/\/+$/, "");
    if (pathname === prefix) return "";
    if (pathname.startsWith(`${prefix}/`)) return pathname.slice(prefix.length);
  }
  return pathname;
}

/**
 * Re-encode one decoded path segment.
 *
 * A framework hands over `params` already decoded, so a segment that arrived as
 * `%2F` is now a literal `/` — joining that back verbatim would let a caller
 * walk outside the path the allowlist checked. Encoding is therefore not
 * cosmetic. `encodeURIComponent` is too aggressive on its own, though: it escapes
 * characters RFC 3986 allows in a segment, and real APIs use them (Google's
 * `models/x:generateContent`, a scope's `@`), so those are put back.
 */
function encodeSegment(segment: string): string {
  return encodeURIComponent(segment).replace(/%(3A|40|24|26|2B|2C|3B|3D)/gi, (escaped) =>
    decodeURIComponent(escaped),
  );
}

function joinUpstream(base: string, path: string, search: string): string {
  const root = base.replace(/\/+$/, "");
  const tail = !path || path === "/" ? "" : path.startsWith("/") ? path : `/${path}`;
  return `${root}${tail}${search}`;
}

function sanitizeRequestHeaders(incoming: Headers): Headers {
  const headers = new Headers();
  incoming.forEach((value, name) => {
    const key = name.toLowerCase();
    if (DROP_REQUEST_HEADERS.has(key)) return;
    // A client-supplied `authorization` is only ever forwarded when it is a
    // placeholder for us to substitute. A real one is either the app's own
    // session (which the upstream must not see) or an attempt to use this route
    // as a general-purpose proxy with someone else's credential.
    if (key === "authorization" && !hasPlaceholder(value)) return;
    headers.set(name, value);
  });
  return headers;
}

function relay(response: Response): Response {
  const headers = new Headers();
  response.headers.forEach((value, name) => {
    if (!DROP_RESPONSE_HEADERS.has(name.toLowerCase())) headers.set(name, value);
  });
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Build the handlers for one upstream.
 *
 * The allowlist is default-deny and is checked twice: once for the operation
 * (host, method, path) on every request, and once per placeholder for the secret
 * itself — the second check is `seekritFetch`'s, unchanged, which is what keeps
 * this handler and the in-process shim pinned to the same substitution vectors.
 */
export function seekritRoute(options: SeekritRouteOptions): SeekritRouteHandlers {
  const {
    upstream,
    authorize,
    scope: deriveScope,
    basePath,
    headers: rewriteHeaders,
    maxBodyBytes = 1024 * 1024,
    maxScopes,
    ...fetchOptions
  } = options;

  if (typeof authorize !== "function") {
    throw new SeekritError(
      "seekritRoute needs { authorize }: a handler that injects credentials for anyone who can " +
        "reach its URL is an open credential proxy. Pass a function that checks your own session.",
    );
  }
  const rules: AllowRule[] = [
    ...(fetchOptions.rules ?? []),
    ...(fetchOptions.allow ? rulesFromAllow(fetchOptions.allow) : []),
  ];
  if (rules.length === 0) {
    throw new SeekritError("seekritRoute needs an allowlist: pass { allow } or { rules }");
  }

  const fetchFor = scopedFetch(fetchOptions, maxScopes);

  async function handle(request: Request, context?: RouteContext): Promise<Response> {
    if (!(await authorize(request))) {
      return textResponse(401, "not authorized to use these credentials", {
        "x-seekrit-refusal": "unauthorized",
      });
    }

    const path = await pathOf(request, context, basePath);
    const { search } = new URL(request.url);
    const resolved =
      typeof upstream === "function"
        ? await upstream(request, path)
        : joinUpstream(upstream, path, search);
    if (!resolved) return textResponse(404, "no upstream for this path");

    let target: URL;
    try {
      target = new URL(resolved);
    } catch {
      throw new SeekritError(`upstream is not an absolute URL: ${JSON.stringify(resolved)}`);
    }

    const method = request.method.toUpperCase();
    // The operation gate. See the note at the top of this file: without it, a
    // request that carries no placeholder would never meet the allowlist.
    const verdict = evaluate(rules, {
      host: target.hostname,
      method,
      path: target.pathname,
    });
    if (verdict.decision !== "allow") return operationRefusal(verdict);

    let body: Uint8Array | undefined;
    if (!BODYLESS_METHODS.has(method)) {
      const declared = Number(request.headers.get("content-length") ?? Number.NaN);
      if (maxBodyBytes > 0 && Number.isFinite(declared) && declared > maxBodyBytes) {
        return textResponse(413, "request body too large");
      }
      const bytes = new Uint8Array(await request.arrayBuffer());
      if (maxBodyBytes > 0 && bytes.byteLength > maxBodyBytes) {
        return textResponse(413, "request body too large");
      }
      // Bytes rather than text on purpose: `seekritFetch` scans them for a
      // placeholder and only re-encodes when it substituted one, so a binary
      // body carrying no placeholder passes through byte-for-byte.
      if (bytes.byteLength > 0) body = bytes;
    }

    const sanitized = sanitizeRequestHeaders(request.headers);
    const headers = rewriteHeaders ? rewriteHeaders(sanitized, request) : sanitized;
    const send = fetchFor(await deriveScope?.(request));

    // `BodyInit` in the DOM lib does not admit a `Uint8Array<ArrayBufferLike>`,
    // though every runtime accepts one and `seekritFetch` scans it. Same class of
    // cast as the ones in packages/crypto, for the same reason.
    const response = await send(target.href, {
      method,
      headers,
      body: body as unknown as BodyInit | undefined,
    });
    return relay(response);
  }

  return {
    GET: handle,
    HEAD: handle,
    POST: handle,
    PUT: handle,
    PATCH: handle,
    DELETE: handle,
    OPTIONS: handle,
    handle,
  };
}

export { placeholder, hasPlaceholder } from "./substitute.js";
export { evaluate, rulesFromAllow, type AllowRule } from "./policy.js";
export type { SeekritFetchScope, ResolveSource } from "./fetch.js";
