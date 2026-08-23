/**
 * Cloudflare Computer adapter — the sandbox holds placeholders, the gateway
 * holds the credentials.
 *
 *     import { seekritEgress, seekritEgressPolicy, seekritEnv } from "@seekrit/sdk/cloudflare-computer";
 *
 *     export class SeekritGateway extends WorkerEntrypoint<Env> {
 *       #egress = seekritEgress({
 *         token: this.env.SEEKRIT_TOKEN,
 *         allow: { "api.openai.com": ["OPENAI_API_KEY"] },
 *       });
 *       override fetch(request: Request) {
 *         return this.#egress.fetch(request);
 *       }
 *     }
 *
 *     // …in the Durable Object that owns the Workspace:
 *     readonly egress = seekritEgressPolicy(this.ctx.exports.SeekritGateway({}), "v1");
 *
 *     // …and the command that runs inside it:
 *     using run = await ws.runtime.exec(
 *       'curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models',
 *       { env: seekritEnv(["OPENAI_API_KEY"]) },
 *     );
 *
 * `$OPENAI_API_KEY` inside the sandbox is the literal string
 * `{{seekrit:OPENAI_API_KEY}}`. The real key is spliced in by
 * {@link seekritEgress}, which runs in *your* Worker — a different isolate,
 * outside the container. Code in the workspace cannot read it, print it, or
 * send it anywhere but the hosts your rules name.
 *
 * **Why this is the strong shape here.** Cloudflare Computer routes every
 * backend's egress — the container's `curl`, the worker shell's `curl`, and
 * `fetch` in the JavaScript isolate — through one `Fetcher` you supply, as
 * already-parsed `Request` objects with the real URL. That is what
 * [`seekrit-proxy`](https://seekrit.dev/docs/guides/agent-proxy) does, minus
 * the parts that make the proxy awkward: no sidecar to run, no `HTTPS_PROXY` to
 * set, and no locally generated CA, because the platform has already terminated
 * TLS by the time the request reaches you. Unlike
 * [`@seekrit/sdk/fetch`](./fetch.ts), the workload cannot bypass it: the
 * gateway is not in the sandbox's address space, and it is the sandbox's only
 * route out.
 *
 * **What it is not.** The rules live in your gateway Worker's own source, which
 * is what makes them trustworthy — the same role `apps/proxy`'s local TOML
 * plays. Rules fetched from an API at runtime would let whoever serves them
 * decide where your credentials go; if you publish signed `ap1.` policy
 * bundles, verify one before you pass its `rules` here.
 *
 * Nothing in this file imports `@cloudflare/computer`. Every shape it touches
 * is declared structurally below, so the adapter cannot break on a version bump
 * and `@seekrit/sdk` stays dependency-free.
 */
import { SeekritError, SeekritSubstitutionError } from "./errors.js";
import { type AllowRule, evaluate, type PolicyDecision, rulesFromAllow } from "./policy.js";
import {
  createPolicySource,
  type PolicySource,
  type PolicySourceOptions,
} from "./policy-source.js";
import { describeOperation, refusalBody, refusalResponse } from "./refusal.js";
import { type ClientSource, createResolver, type ResolveSource } from "./resolver.js";
import { hasPlaceholder, type Lookup, placeholder, substitute } from "./substitute.js";

/** `apps/proxy`'s default, and for the same reason: a body is buffered to scan it. */
const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;

/** The one method Cloudflare Computer needs from an egress gateway. */
export interface SeekritEgressGateway {
  fetch(request: Request): Promise<Response>;
}

/** Why the gateway refused. Names and constraints only — never a value. */
export interface SeekritEgressRefusal {
  /**
   * `"operation"` — no rule permits this host, method, or path, so the request
   * was never sent. `"denied"` / `"unresolved"` — the operation was permitted
   * but a placeholder in it was not. `"bad_request"` — the request could not be
   * handled safely (an unbuffered body, or a placeholder that rewrote the host).
   */
  reason: "operation" | "denied" | "unresolved" | "bad_request" | "no_policy";
  host: string;
  method: string;
  path: string;
  /** Present when `reason` is `"operation"`. */
  decision?: PolicyDecision;
  /** Present when `reason` is `"denied"` or `"unresolved"`. */
  secretName?: string;
  /** The same text the sandbox receives in the 403/400 body. */
  message: string;
}

export interface SeekritEgressOptions {
  /** Shorthand: `{ "api.openai.com": ["OPENAI_API_KEY"] }`, any method or path. */
  allow?: Record<string, string[]>;
  /**
   * Full rules, host by host. This is the wire shape of a signed `ap1.` bundle's
   * `rules`, so a verified bundle's array can be passed straight in.
   *
   * A rule with `allow: []` is the useful special case: the sandbox may reach
   * that host, and no secret may be injected toward it. That is how you let an
   * agent `pip install` without letting it carry a credential to PyPI.
   */
  rules?: AllowRule[];
  /**
   * Take the rules from a **signed `ap1.` bundle** instead of from this file,
   * verified against signers you pin here.
   *
   * This is how a narrowing published from the dashboard reaches a deployed
   * Worker without a redeploy. It is safe for the same reason the proxy's
   * server mode is: the API stores a blob it cannot forge, and nothing is
   * enforced until the signature checks out against `policy.signers`, which
   * come from your config and not from the API.
   *
   * Mutually exclusive with `allow` / `rules`. To bound what a published bundle
   * may ever say here, set `policy.ceiling`.
   */
  policy?: PolicySourceOptions;
  /** `skt_…` service token. Defaults to `$SEEKRIT_TOKEN`. */
  token?: string;
  /** API base URL. Defaults to `$SEEKRIT_API_URL`. */
  apiUrl?: string;
  /** `{ groupSlug: envSlug }` overrides — which slice this workspace resolves. */
  with?: Record<string, string>;
  /** Where resolved values come from. Omit and one is built from `token`. */
  client?: ClientSource;
  /**
   * How long a resolved set may be reused (default 60). `0` resolves on every
   * request that carries a placeholder. Values live in memory only, in the
   * gateway isolate — never in the sandbox.
   */
  ttlSeconds?: number;
  /**
   * Also scan the request body (default `true`).
   *
   * Scanning means buffering, capped at {@link maxBodyBytes}: a body over the
   * cap is refused rather than forwarded unscanned, which is what `apps/proxy`
   * does and for the same reason — silently skipping the scan would forward a
   * literal placeholder to the upstream. Set `false` to stream every body
   * through untouched, and keep your placeholders in headers and URLs.
   */
  body?: boolean;
  /** Cap on a scanned body (default 2 MiB). Ignored when `body` is `false`. */
  maxBodyBytes?: number;
  /** The fetch the gateway sends upstream with. Defaults to the global. */
  fetch?: typeof globalThis.fetch;
  /** Notified after a successful substitution. Names only — never values. */
  onInject?: (event: { host: string; method: string; path: string; names: string[] }) => void;
  /** Notified on every refusal. This is the security-significant event. */
  onRefuse?: (refusal: SeekritEgressRefusal) => void;
}

/**
 * Build the egress gateway for a Workspace: default-deny, with
 * `{{seekrit:NAME}}` substituted into whatever it lets through.
 *
 * Every request is checked twice. First the *operation* — host, method, path —
 * against the rules; a request no rule covers is answered 403 and never sent,
 * so the gateway is an egress firewall and not only a credential shim. Then
 * each placeholder it carries, against the same rules; a name that host may not
 * receive is answered 403 and never sent either.
 *
 * Redirects are never followed here (`redirect: "manual"`): following one would
 * carry a substituted credential to a location no rule authorised. The 3xx goes
 * back to the sandbox, and if it follows the redirect that request arrives at
 * this gateway on its own account.
 */
export function seekritEgress(options: SeekritEgressOptions = {}): SeekritEgressGateway {
  const staticRules: AllowRule[] = [
    ...(options.rules ?? []),
    ...(options.allow ? rulesFromAllow(options.allow) : []),
  ];
  if (options.policy && staticRules.length > 0) {
    throw new SeekritError(
      "pass either a static allowlist or { policy }, not both — to bound what a signed bundle " +
        "may say here, set policy.ceiling",
    );
  }
  if (!options.policy && staticRules.length === 0) {
    throw new SeekritError(
      "seekritEgress needs an allowlist: pass { allow }, { rules }, or { policy }",
    );
  }
  const source: PolicySource | undefined = options.policy
    ? createPolicySource(options.policy)
    : undefined;

  const scanBody = options.body ?? true;
  const maxBodyBytes = Math.max(0, options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES);
  const plainFetch = options.fetch ?? globalThis.fetch;
  if (typeof plainFetch !== "function") {
    throw new SeekritError("no global fetch available; pass { fetch } explicitly");
  }
  const send = plainFetch.bind(globalThis);
  const resolver = createResolver({
    token: options.token,
    apiUrl: options.apiUrl,
    client: options.client,
    ttlSeconds: options.ttlSeconds,
    fetch: send,
  });

  function refuse(refusal: SeekritEgressRefusal, response: Response): Response {
    options.onRefuse?.(refusal);
    return response;
  }

  async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const host = url.hostname;
    const method = request.method.toUpperCase();
    const path = url.pathname;
    const where = { host, method, path };

    // 0. The rules in force. With a signed source this can fetch and verify;
    //    with none to trust, nothing is permitted — the same answer the proxy
    //    gives, rather than falling back to something more permissive.
    let rules: AllowRule[];
    if (source) {
      try {
        rules = (await source.current()).rules;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return refuse(
          { reason: "no_policy", ...where, message },
          new Response(message, {
            status: 403,
            statusText: "Forbidden",
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "x-seekrit-refusal": "no_policy",
            },
          }),
        );
      }
    } else {
      rules = staticRules;
    }

    // 1. The operation. Default-deny, before anything is read or resolved.
    const verdict = evaluate(rules, where);
    if (verdict.decision !== "allow") {
      const message = describeOperation(verdict.decision);
      return refuse(
        { reason: "operation", ...where, decision: verdict.decision, message },
        new Response(message, {
          status: 403,
          statusText: "Forbidden",
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "x-seekrit-refusal": verdict.decision,
          },
        }),
      );
    }

    // 2. What this request says. A body is buffered only when it might carry a
    //    placeholder, and only up to the cap.
    const headers = new Headers(request.headers);
    let bodyBuffer: ArrayBuffer | undefined;
    let bodyText: string | undefined;

    if (scanBody && request.body !== null) {
      const buffered = await readCapped(request.body, maxBodyBytes);
      if (buffered === null) {
        const message = `could not buffer request body for substitution (limit ${maxBodyBytes} bytes)`;
        return refuse(
          { reason: "bad_request", ...where, message },
          new Response(message, {
            status: 400,
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "x-seekrit-refusal": "body_too_large",
            },
          }),
        );
      }
      bodyBuffer = buffered;
      // A body that is not valid UTF-8 is binary: it cannot hold a placeholder,
      // and decoding it lossily would corrupt the upload on the way back out.
      try {
        bodyText = new TextDecoder("utf-8", { fatal: true }).decode(buffered);
      } catch {
        bodyText = undefined;
      }
    }

    // `new URL()` percent-encodes `{` and `}` in a *path* (they are in the path
    // encode set but not the query one), so a placeholder that arrived in a path
    // reaches us as `%7B%7Bseekrit:NAME%7D%7D` and would never match. Put the
    // markers back before scanning. Re-encoding on the way out is lossless, so a
    // stray encoded brace pair that is not part of a placeholder round-trips.
    const href = decodeMarkers(url.href);
    let touched = hasPlaceholder(href);
    if (!touched) {
      headers.forEach((value) => {
        if (!touched && hasPlaceholder(value)) touched = true;
      });
    }
    if (!touched && bodyText !== undefined) touched = hasPlaceholder(bodyText);

    // 3. Substitute, if there is anything to substitute. A request carrying no
    //    placeholder never triggers a resolve — a workspace can use this gateway
    //    as a plain allowlist and never hold a token at all.
    let outUrl = url.href;
    let outBody: BodyInit | undefined = bodyBuffer;
    let outHeaders = headers;
    if (touched) {
      const values = await resolver(options.with);
      const injected = new Set<string>();
      const lookup = (name: string): Lookup => {
        const decision = evaluate(rules, { ...where, secret: name }).decision;
        if (decision !== "allow") return { kind: "denied", reason: decision };
        const value = values[name];
        if (value === undefined) return { kind: "unknown" };
        injected.add(name);
        return { kind: "value", value };
      };

      try {
        outUrl = substitute(href, lookup).text;
        // A fresh Headers rather than a mutation, so the iteration is over a list
        // nobody is editing underneath it.
        const next = new Headers();
        headers.forEach((value, name) => {
          next.set(name, substitute(value, lookup).text);
        });
        outHeaders = next;
        if (bodyText !== undefined) {
          const rewritten = substitute(bodyText, lookup).text;
          // Re-encode only on a change, so an untouched body stays byte-for-byte.
          if (rewritten !== bodyText) outBody = new TextEncoder().encode(rewritten);
        }
      } catch (error) {
        if (error instanceof SeekritSubstitutionError) {
          return refuse(
            {
              reason: error.code === "denied" ? "denied" : "unresolved",
              ...where,
              secretName: error.secretName,
              message: refusalBody(error),
            },
            refusalResponse(error),
          );
        }
        throw error;
      }

      // Defence in depth: the operation was authorised for *this* origin, so a
      // substitution that moved the request elsewhere would hand the credential
      // to a host no rule covers. A placeholder can only sit after the authority,
      // so this should not be reachable — which is the point of checking.
      let rewritten: URL | undefined;
      try {
        rewritten = new URL(outUrl);
      } catch {
        rewritten = undefined;
      }
      if (rewritten?.protocol !== url.protocol || rewritten.host !== url.host) {
        const message =
          "a placeholder may not change the scheme, host, or port of a request";
        return refuse(
          { reason: "bad_request", ...where, message },
          new Response(message, {
            status: 400,
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "x-seekrit-refusal": "url_rewritten",
            },
          }),
        );
      }

      if (injected.size > 0) {
        options.onInject?.({ ...where, names: [...injected].sort() });
      }
    }

    // Whatever the sandbox claimed, the length is ours now: substitution changes
    // it, and a stale `content-length` is a truncated request at the upstream.
    // The runtime recomputes it from the buffer we hand it.
    if (outBody !== undefined) outHeaders.delete("content-length");

    const init: RequestInit = { method, headers: outHeaders, redirect: "manual" };
    if (outBody !== undefined) {
      init.body = outBody;
    } else if (request.body !== null) {
      // Not scanning: stream it through untouched.
      init.body = request.body;
      (init as { duplex?: string }).duplex = "half";
    }
    return send(outUrl, init);
  }

  return { fetch: (request: Request) => handle(request) };
}

/** Undo the URL parser's encoding of the placeholder's own delimiters. */
function decodeMarkers(href: string): string {
  return href.replace(/%7B%7Bseekrit:/gi, "{{seekrit:").replace(/%7D%7D/gi, "}}");
}

/**
 * Read a body, refusing rather than truncating past `max`. Returns `null` when
 * the cap is exceeded — fail-closed, because a half-scanned body is a body
 * whose placeholders we did not see.
 */
async function readCapped(
  body: ReadableStream<Uint8Array>,
  max: number,
): Promise<ArrayBuffer | null> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > max) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const buffer = new ArrayBuffer(total);
  const out = new Uint8Array(buffer);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return buffer;
}

/**
 * Wrap a gateway as a Workspace egress policy.
 *
 * Generic in the gateway so the real `Fetcher` type survives — pass what
 * `ctx.exports.YourGateway({})` gives you.
 *
 * Set `revision` to something that changes when your gateway's behaviour
 * changes. Cloudflare Computer keys its dynamic-worker cache on it, and with no
 * revision it uses a fresh id per call, so every `exec` pays for a cold worker.
 */
export function seekritEgressPolicy<G>(
  gateway: G,
  revision?: string,
): { mode: "http-gateway"; gateway: G; revision?: string } {
  return revision === undefined
    ? { mode: "http-gateway", gateway }
    : { mode: "http-gateway", gateway, revision };
}

/** `["A", "B"]`, or `{ ENV_NAME: "SECRET_NAME" }` when the two differ. */
export type EnvNames = string[] | Record<string, string>;

function entriesOf(names: EnvNames): [string, string][] {
  return Array.isArray(names) ? names.map((name) => [name, name]) : Object.entries(names);
}

/**
 * Environment variables that are placeholders, not credentials.
 *
 *     await ws.runtime.exec("./deploy.sh", { env: seekritEnv(["STRIPE_SECRET_KEY"]) });
 *
 * The command sees `STRIPE_SECRET_KEY={{seekrit:STRIPE_SECRET_KEY}}`. Anything
 * it sends that carries the value — a header, a query parameter, a JSON body —
 * arrives at {@link seekritEgress} with the placeholder in it, and leaves with
 * the credential. A `printenv` in the sandbox, a leaked log, or a prompt
 * injection that exfiltrates the whole environment yields markers.
 *
 * This only works for a workspace whose egress goes through the gateway. With
 * `{ mode: "direct" }` the placeholder reaches the upstream verbatim and the
 * call fails — loudly, which is the right way for that mistake to surface.
 */
export function seekritEnv(names: EnvNames): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [variable, secret] of entriesOf(names)) {
    env[variable] = placeholder(secret);
  }
  return env;
}

/**
 * Environment variables that are the real values — for the other case.
 *
 *     const client = new Seekrit({ token: env.SEEKRIT_TOKEN });
 *     await ws.runtime.exec("npm run migrate", {
 *       env: await resolveEnv(client, ["DATABASE_URL"]),
 *     });
 *
 * Use this when the code in the workspace is *yours* — a build, a migration, a
 * test run — and the credential is one the command must hold rather than send.
 * A `psql` connection is not an HTTP request and no egress gateway can inject
 * into it.
 *
 * Named secrets only, never the whole resolved set: a command should not get a
 * credential just because it exists. Fail-closed on a name that did not
 * resolve, because the alternative is a command that runs with the variable
 * unset and fails somewhere less obvious.
 */
export async function resolveEnv(
  source: ResolveSource,
  names: EnvNames,
): Promise<Record<string, string>> {
  const values = await source.resolve();
  const env: Record<string, string> = {};
  const missing: string[] = [];
  for (const [variable, secret] of entriesOf(names)) {
    const value = values[secret];
    if (value === undefined) missing.push(secret);
    else env[variable] = value;
  }
  if (missing.length > 0) {
    throw new SeekritError(`resolved no secret named ${missing.sort().join(", ")}`);
  }
  return env;
}

// Re-exported so a gateway Worker needs one import.
export { placeholder, hasPlaceholder, substitute, type Lookup } from "./substitute.js";
export {
  evaluate,
  rulesFromAllow,
  type AllowRule,
  type PolicyDecision,
  type PolicyQuery,
  type PolicyVerdict,
} from "./policy.js";
export type { ClientSource, ResolveSource } from "./resolver.js";
export {
  checkPolicyBundleContext,
  checkPolicyCeiling,
  parsePolicyBundleUnverified,
  policySignerThumbprint,
  SeekritPolicyError,
  verifyPolicyBundle,
  type PolicyBundle,
  type PolicyBundleRule,
  type PolicyCeiling,
  type PolicySignerJwk,
} from "./policy-bundle.js";
export {
  createPolicySource,
  type LoadedPolicy,
  type PolicyEvent,
  type PolicySource,
  type PolicySourceOptions,
  type PolicyStore,
} from "./policy-source.js";
export { SeekritError, SeekritSubstitutionError } from "./errors.js";
