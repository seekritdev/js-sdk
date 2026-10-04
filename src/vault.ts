/**
 * `@seekrit/sdk/vault` — the platform side of Seekrit Vault.
 *
 *     import { Vault } from "@seekrit/sdk/vault";
 *
 *     const vault = new Vault({
 *       key: env.SEEKRIT_VAULT_KEY,              // skv_… from the dashboard
 *       executorUrl: env.VAULT_EXECUTOR_URL,     // your executor Worker
 *       executorToken: env.VAULT_EXECUTOR_TOKEN, // its EXECUTOR_TOKEN secret
 *     });
 *
 *     const { url } = await vault.connect.create({ userRef: "u_123", providerId: "resend" });
 *     // text `url` to the user …
 *
 *     const res = await vault.fetch({
 *       userRef: "u_123",
 *       connectionId,
 *       request: { method: "POST", url: "https://api.resend.com/emails", body },
 *     });
 *
 *     // A site with no API: a signed-in browser for your own tools.
 *     const lease = await vault.browser.open({ userRef: "u_123", connectionId });
 *     // … drive lease.sessionId with your browser tooling …
 *     await vault.browser.release({ userRef: "u_123", leaseId: lease.leaseId });
 *
 * Three environment variables, two endpoints, and **no credential ever in this
 * process**: the hosted API holds ciphertext it cannot open, your executor (a
 * Worker in your own Cloudflare account) decrypts just in time and applies the
 * credential to the outbound request, and your code — including the agent that
 * asked for the request — only ever sees the provider's response with any echo
 * of the credential redacted.
 *
 * ### The link is built here, on purpose
 *
 * A Connect link carries three things in its **fragment** (never sent to any
 * server): the connect token `t`, your executor's origin `x`, and the
 * thumbprint `k` of its wrapping key. `t` comes from the hosted API; `x` and `k`
 * come from *your* executor's `GET /v1/identity`, which this SDK reads (and
 * caches). The Connect page refuses to continue unless the executor at `x`
 * presents the key `k`. So an attacker who controls the hosted API or its
 * database still cannot point your users at a different executor or key — the
 * pin is built from a source they do not control.
 */
import { SeekritApiError, SeekritError } from "./errors.js";

export const DEFAULT_VAULT_API_URL = "https://api.seekrit.dev";
export const DEFAULT_CONNECT_URL = "https://connect.seekrit.dev";

export interface VaultOptions {
  /** `skv_…` platform key. Defaults to `$SEEKRIT_VAULT_KEY`. */
  key?: string;
  /** Hosted Vault API. Defaults to `$SEEKRIT_API_URL` or `https://api.seekrit.dev`. */
  apiUrl?: string;
  /** Your executor Worker's origin. Defaults to `$VAULT_EXECUTOR_URL`. */
  executorUrl?: string;
  /** Your executor's `EXECUTOR_TOKEN`. Defaults to `$VAULT_EXECUTOR_TOKEN`. */
  executorToken?: string;
  /** The hosted Connect page. Defaults to `https://connect.seekrit.dev`. */
  connectUrl?: string;
  /** Custom fetch (defaults to the global). */
  fetch?: typeof globalThis.fetch;
}

export type VaultMethod = "oauth2" | "api_key" | "browser";
export type VaultSlot = "oauth2" | "api_key" | "session" | "login";
export type VaultConnectionStatus = "active" | "reauth_required" | "revoked";

export interface VaultConnection {
  id: string;
  projectId: string;
  userRef: string;
  providerId: string;
  method: VaultMethod;
  accountLabel: string | null;
  status: VaultConnectionStatus;
  statusReason: string | null;
  slots: Array<{ slot: VaultSlot; revision: number; updatedAt: string }>;
  consentedAt: string;
  consentVersion: number;
  expiresAt: string | null;
  revokedAt: string | null;
  revokedBy: "platform" | "end_user" | "org_admin" | "system" | null;
  lastUsedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface VaultConnectSession {
  id: string;
  purpose: "connect" | "reconnect" | "manage";
  userRef: string;
  /** Null for a manage session. */
  providerId: string | null;
  method: VaultMethod | null;
  status: "pending" | "completed" | "expired" | "cancelled";
  /** Set once the person has completed the flow. */
  connectionId: string | null;
  expiresAt: string;
  claimedAt: string | null;
  consentedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface CreateConnectInput {
  /** Your opaque id for the end user. Never an email address. */
  userRef: string;
  /** A provider or site id from your executor's `vault.config.ts`. */
  providerId: string;
  /** `reconnect` repairs `connectionId` instead of creating a new connection. */
  purpose?: "connect" | "reconnect";
  connectionId?: string;
  /** Where the done screen may send the person; its origin must be registered on the project. */
  returnUrl?: string;
  /** Link lifetime, 60s–24h (default one hour). */
  expiresInSeconds?: number;
}

export interface CreatedConnect {
  /** The connect session id, for `connect.get`. */
  id: string;
  /** The link to send to the person. Everything sensitive is in its fragment. */
  url: string;
  /** The connection this link will create (or repair). */
  connectionId: string;
  method: VaultMethod;
  expiresAt: string;
}

export interface VaultFetchInput {
  userRef: string;
  connectionId: string;
  request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    /** UTF-8 text. Carry `{{seekrit:API_KEY}}` / `{{seekrit:ACCESS_TOKEN}}` to place the credential yourself. */
    body?: string;
  };
}

export interface ExecutorIdentity {
  origin: string;
  thumbprint: string;
}

export interface CreateManageInput {
  /** Your opaque id for the end user. */
  userRef: string;
  /** Where the manage page's "back" button goes; its origin must be registered on the project. */
  returnUrl?: string;
  /** Link lifetime, 60s–24h (default one hour). */
  expiresInSeconds?: number;
}

export interface CreatedManage {
  id: string;
  /** The link to send to the person. */
  url: string;
  expiresAt: string;
}

/** A signed-in browser for your own tools: connect to `sessionId` and drive it. */
export interface BrowserLease {
  leaseId: string;
  sessionId: string;
  targetId: string;
  expiresAt: string;
  /** The restored session landed somewhere other than a sign-in page. */
  signedIn: boolean;
}

export type FillField = "username" | "password" | "totp";

export type WebhookEventType =
  | "connection.ready"
  | "connection.reauth_required"
  | "connection.revoked";

export interface WebhookEndpoint {
  id: string;
  projectId: string;
  url: string;
  events: WebhookEventType[];
  description: string | null;
  status: "active" | "disabled";
  failureCount: number;
  lastDeliveryAt: string | null;
  lastDeliveryStatus: number | null;
  lastError: string | null;
  createdAt: string;
}

/** The body of a delivery. `connection` is null for a `ping`. */
export interface WebhookEvent {
  id: string;
  type: WebhookEventType | "ping";
  createdAt: string;
  projectId: string;
  data: { connection: VaultConnection | null };
}

export const WEBHOOK_SIGNATURE_HEADER = "seekrit-webhook-signature";
export const WEBHOOK_ID_HEADER = "seekrit-webhook-id";
export const WEBHOOK_TIMESTAMP_HEADER = "seekrit-webhook-timestamp";

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * Verify a webhook delivery: `v1=<hex hmac-sha256(secret, "id.timestamp.body")>`
 * over the raw body, with the id and timestamp from the delivery's headers.
 * Deliveries older than `toleranceSeconds` (default five minutes) are refused.
 *
 *     const event = await verifyWebhook({ secret, headers: req.headers, body: await req.text() });
 *     if (!event) return new Response("bad signature", { status: 400 });
 */
export async function verifyWebhook(input: {
  secret: string;
  /** The request's headers (a `Headers` or a plain object, lower-case names). */
  headers: Headers | Record<string, string | undefined>;
  /** The raw request body, exactly as received. */
  body: string;
  toleranceSeconds?: number;
  now?: number;
}): Promise<WebhookEvent | null> {
  const get = (name: string) =>
    input.headers instanceof Headers
      ? input.headers.get(name)
      : (input.headers[name] ?? input.headers[name.toLowerCase()] ?? null);
  const id = get(WEBHOOK_ID_HEADER);
  const timestamp = get(WEBHOOK_TIMESTAMP_HEADER);
  const signature = get(WEBHOOK_SIGNATURE_HEADER);
  if (!id || !timestamp || !signature) return null;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return null;
  const now = Math.floor((input.now ?? Date.now()) / 1000);
  if (Math.abs(now - ts) > (input.toleranceSeconds ?? 300)) return null;
  const key = await crypto.subtle.importKey(
    "raw",
    utf8(input.secret) as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, utf8(`${id}.${timestamp}.${input.body}`) as BufferSource),
  );
  const expected = `v1=${[...mac].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  const presented = signature.trim();
  if (presented.length !== expected.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ presented.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    const event = JSON.parse(input.body) as WebhookEvent;
    return event.id === id ? event : null;
  } catch {
    return null;
  }
}

/** Read an env var across Node/Bun/Deno; undefined in the browser. */
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
 * Build a Connect link. Exported on its own so a backend that stores the
 * executor identity elsewhere can still produce a correctly pinned link.
 */
export function buildConnectUrl(
  link: { token: string; executorOrigin: string; keyThumbprint: string },
  connectUrl: string = DEFAULT_CONNECT_URL,
): string {
  const origin = new URL(link.executorOrigin);
  if (origin.origin !== link.executorOrigin) {
    throw new SeekritError("executorOrigin must be a bare origin (scheme + host, nothing else)");
  }
  const params = new URLSearchParams({
    t: link.token,
    x: link.executorOrigin,
    k: link.keyThumbprint,
  });
  return `${connectUrl.replace(/\/+$/, "")}/#${params.toString()}`;
}

/** The executor refused or could not perform a request. */
export class VaultExecutorError extends SeekritError {
  readonly status: number;
  /** The executor's error code — `not_allowed`, `user_mismatch`, `connection_revoked`, … */
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(`${status} ${code}: ${message}`);
    this.name = "VaultExecutorError";
    this.status = status;
    this.code = code;
  }
}

export class Vault {
  private readonly key: string;
  private readonly apiUrl: string;
  private readonly executorUrl: string;
  private readonly executorToken: string;
  private readonly connectUrl: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private identityPromise?: Promise<ExecutorIdentity>;

  constructor(options: VaultOptions = {}) {
    const key = options.key ?? readEnv("SEEKRIT_VAULT_KEY");
    if (!key) throw new SeekritError("no platform key: pass { key } or set SEEKRIT_VAULT_KEY");
    if (!key.startsWith("skv_")) {
      throw new SeekritError("a Vault platform key starts with skv_ (a service token will not do)");
    }
    const executorUrl = options.executorUrl ?? readEnv("VAULT_EXECUTOR_URL");
    if (!executorUrl) {
      throw new SeekritError("no executor: pass { executorUrl } or set VAULT_EXECUTOR_URL");
    }
    const executorToken = options.executorToken ?? readEnv("VAULT_EXECUTOR_TOKEN");
    if (!executorToken) {
      throw new SeekritError(
        "no executor token: pass { executorToken } or set VAULT_EXECUTOR_TOKEN",
      );
    }
    this.key = key;
    this.executorUrl = new URL(executorUrl).origin;
    this.executorToken = executorToken;
    this.apiUrl = (options.apiUrl ?? readEnv("SEEKRIT_API_URL") ?? DEFAULT_VAULT_API_URL).replace(
      /\/+$/,
      "",
    );
    this.connectUrl = (options.connectUrl ?? DEFAULT_CONNECT_URL).replace(/\/+$/, "");
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new SeekritError("no global fetch available; pass { fetch } explicitly");
    }
    this.fetchImpl = fetchImpl.bind(globalThis);
  }

  // ── hosted API ───────────────────────────────────────────────────────────

  private async api<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {
      accept: "application/json",
      authorization: `Bearer ${this.key}`,
      "x-seekrit-client": "sdk-js/vault",
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await this.fetchImpl(`${this.apiUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      const fallback = { error: { code: "internal", message: `HTTP ${res.status}` } };
      const payload = (await res.json().catch(() => fallback)) as typeof fallback;
      throw new SeekritApiError(
        res.status,
        payload.error?.code ?? "internal",
        payload.error?.message ?? `HTTP ${res.status}`,
      );
    }
    return (await res.json()) as T;
  }

  // ── executor ─────────────────────────────────────────────────────────────

  private async executor(method: string, path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = {
      accept: "application/json",
      authorization: `Bearer ${this.executorToken}`,
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    return this.fetchImpl(`${this.executorUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  private async executorJson<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.executor(method, path, body);
    if (!res.ok) throw await executorError(res);
    return (await res.json()) as T;
  }

  /**
   * Your executor's origin and current wrapping-key thumbprint — the `x` and
   * `k` of every Connect link. Fetched once and cached for the client's life;
   * an executor that rotates its key is picked up by a new `Vault` instance.
   */
  identity(): Promise<ExecutorIdentity> {
    this.identityPromise ??= this.executorJson<ExecutorIdentity>("GET", "/v1/identity").catch(
      (err) => {
        this.identityPromise = undefined;
        throw err;
      },
    );
    return this.identityPromise;
  }

  readonly connect = {
    /** Open a connect session and build the link to text the person. */
    create: async (input: CreateConnectInput): Promise<CreatedConnect> => {
      const [identity, created] = await Promise.all([
        this.identity(),
        this.api<{
          session: {
            id: string;
            token: string;
            expiresAt: string;
            method: VaultMethod;
            connectionId: string;
          };
        }>("POST", "/v1/vault/connect-sessions", input),
      ]);
      const { session } = created;
      return {
        id: session.id,
        url: buildConnectUrl(
          {
            token: session.token,
            executorOrigin: identity.origin,
            keyThumbprint: identity.thumbprint,
          },
          this.connectUrl,
        ),
        connectionId: session.connectionId,
        method: session.method,
        expiresAt: session.expiresAt,
      };
    },
    /** Poll a session; `connectionId` is set once the person has finished. */
    get: async (sessionId: string): Promise<VaultConnectSession> =>
      (
        await this.api<{ session: VaultConnectSession }>(
          "GET",
          `/v1/vault/connect-sessions/${encodeURIComponent(sessionId)}`,
        )
      ).session,
  };

  readonly manage = {
    /** A link where the person sees every connection you hold for them and can disconnect any. */
    create: async (input: CreateManageInput): Promise<CreatedManage> => {
      const [identity, created] = await Promise.all([
        this.identity(),
        this.api<{ session: { id: string; token: string; expiresAt: string } }>(
          "POST",
          "/v1/vault/manage-sessions",
          input,
        ),
      ]);
      return {
        id: created.session.id,
        url: buildConnectUrl(
          {
            token: created.session.token,
            executorOrigin: identity.origin,
            keyThumbprint: identity.thumbprint,
          },
          this.connectUrl,
        ),
        expiresAt: created.session.expiresAt,
      };
    },
  };

  readonly webhooks = {
    /** Register an endpoint. The returned `secret` is shown once; verify deliveries with {@link verifyWebhook}. */
    create: async (input: {
      url: string;
      events?: WebhookEventType[];
      description?: string;
    }): Promise<{ endpoint: WebhookEndpoint; secret: string }> =>
      this.api("POST", "/v1/vault/webhooks", input),
    list: async (): Promise<{ endpoints: WebhookEndpoint[]; available: boolean }> =>
      this.api("GET", "/v1/vault/webhooks"),
    delete: async (endpointId: string): Promise<void> => {
      await this.api("DELETE", `/v1/vault/webhooks/${encodeURIComponent(endpointId)}`);
    },
    /** Send a `ping`. */
    test: async (
      endpointId: string,
    ): Promise<{
      deliveryId: string;
      delivered: boolean | null;
      status: number | null;
      error: string | null;
      queued: boolean;
    }> => this.api("POST", `/v1/vault/webhooks/${encodeURIComponent(endpointId)}/test`),
  };

  /**
   * Browser sites (`siteProfile` in your executor's config): a Browser Run
   * session, already signed in, that your own browser tools drive. Cookies
   * never reach this process; `release` writes the rotated session back.
   */
  readonly browser = {
    open: async (input: {
      userRef: string;
      connectionId: string;
      keepAliveMs?: number;
    }): Promise<BrowserLease> => this.executorJson("POST", "/v1/browser/open", input),
    /** Type a saved login field into the focused input — on the site's login origins only. */
    fill: async (input: {
      userRef: string;
      leaseId: string;
      field: FillField;
    }): Promise<{ filled: true }> => this.executorJson("POST", "/v1/browser/fill", input),
    /** Save the rotated session (unless `save: false`) and close the browser. */
    release: async (input: {
      userRef: string;
      leaseId: string;
      save?: boolean;
    }): Promise<{ saved: boolean; signedIn: boolean | null }> =>
      this.executorJson("POST", "/v1/browser/release", input),
    /** A Live View link for the *person* to sign in again. Forward it to them; never log it. */
    reauth: async (input: {
      userRef: string;
      leaseId: string;
    }): Promise<{ liveViewUrl: string; expiresAt: string }> =>
      this.executorJson("POST", "/v1/browser/reauth", input),
  };

  readonly connections = {
    list: async (query: {
      userRef?: string;
      status?: VaultConnectionStatus;
      cursor?: string;
      limit?: number;
    } = {}): Promise<{ connections: VaultConnection[]; nextCursor: string | null }> => {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) if (v !== undefined) params.set(k, String(v));
      const qs = params.toString();
      return this.api("GET", `/v1/vault/connections${qs ? `?${qs}` : ""}`);
    },
    get: async (connectionId: string): Promise<VaultConnection> =>
      (
        await this.api<{ connection: VaultConnection }>(
          "GET",
          `/v1/vault/connections/${encodeURIComponent(connectionId)}`,
        )
      ).connection,
    /** Revoke: the executor can no longer release this credential, immediately. */
    revoke: async (connectionId: string): Promise<VaultConnection> =>
      (
        await this.api<{ connection: VaultConnection }>(
          "DELETE",
          `/v1/vault/connections/${encodeURIComponent(connectionId)}`,
        )
      ).connection,
  };

  /**
   * Send a provider request *as the user*, through your executor. The
   * credential is decrypted there, applied there, and redacted from the
   * response there; this process sees neither it nor its ciphertext.
   *
   * Resolves to the provider's `Response` (status, headers, streaming body).
   * Throws {@link VaultExecutorError} when the executor itself refuses — a host
   * outside the provider's rules, a `userRef` that does not own the connection,
   * a revoked connection — so a refusal is never mistaken for a provider error.
   */
  async fetch(input: VaultFetchInput): Promise<Response> {
    const res = await this.executor("POST", "/v1/fetch", input);
    if (res.headers.get("x-seekrit-vault-error")) throw await executorError(res);
    return res;
  }
}

async function executorError(res: Response): Promise<VaultExecutorError> {
  const fallback = { error: { code: "internal", message: `HTTP ${res.status}` } };
  const payload = (await res
    .clone()
    .json()
    .catch(() => fallback)) as typeof fallback;
  return new VaultExecutorError(
    res.status,
    payload.error?.code ?? "internal",
    payload.error?.message ?? `HTTP ${res.status}`,
  );
}

export { SeekritApiError, SeekritError } from "./errors.js";
