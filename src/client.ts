import { materialize, TokenKey } from "./crypto.js";
import { SeekritApiError, SeekritError } from "./errors.js";
import type { ResolveResponse } from "./types.js";

export const DEFAULT_API_URL = "https://api.seekrit.dev";

export interface SeekritOptions {
  /** `skt_...` service token. Defaults to `$SEEKRIT_TOKEN`. */
  token?: string;
  /** API base URL. Defaults to `$SEEKRIT_API_URL` or `https://api.seekrit.dev`. */
  apiUrl?: string;
  /** `{ groupSlug: envSlug }` overrides — pull a different slice of a composed group. */
  with?: Record<string, string>;
  /** Custom fetch implementation (defaults to the global `fetch`). */
  fetch?: typeof globalThis.fetch;
}

/** Read an env var across Node/Bun/Deno; returns undefined in the browser. */
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

/**
 * A read-only seekrit client bound to one service token. A service token
 * selects exactly one app environment (plus its composed group slices).
 *
 *     const client = new Seekrit();          // token from $SEEKRIT_TOKEN
 *     const secrets = await client.resolve(); // { DATABASE_URL: "...", ... }
 */
export class Seekrit {
  private readonly token: string;
  private readonly apiUrl: string;
  private readonly with: Record<string, string>;
  private readonly fetchImpl: typeof globalThis.fetch;
  private keyPromise?: Promise<TokenKey>;

  constructor(options: SeekritOptions = {}) {
    const token = options.token ?? readEnv("SEEKRIT_TOKEN");
    if (!token) {
      throw new SeekritError("no service token: pass { token } or set SEEKRIT_TOKEN");
    }
    this.token = token;
    this.apiUrl = (options.apiUrl ?? readEnv("SEEKRIT_API_URL") ?? DEFAULT_API_URL).replace(
      /\/+$/,
      "",
    );
    this.with = options.with ?? {};
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new SeekritError("no global fetch available; pass { fetch } explicitly");
    }
    this.fetchImpl = fetchImpl.bind(globalThis);
  }

  /** Fetch, decrypt, and merge; resolves to `{ NAME: value }`. Fail-closed. */
  async resolve(): Promise<Record<string, string>> {
    const [response, key] = await Promise.all([this.fetch(), this.parseKey()]);
    return materialize(response, key);
  }

  /** Resolve and return a single secret's value, or `undefined` if absent. */
  async get(name: string): Promise<string | undefined> {
    return (await this.resolve())[name];
  }

  private parseKey(): Promise<TokenKey> {
    this.keyPromise ??= TokenKey.parse(this.token);
    return this.keyPromise;
  }

  private async fetch(): Promise<ResolveResponse> {
    const params = new URLSearchParams();
    for (const group of Object.keys(this.with).sort()) {
      params.append("with", `${group}:${this.with[group]}`);
    }
    const query = params.toString();
    const url = `${this.apiUrl}/v1/resolve${query ? `?${query}` : ""}`;

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        headers: { authorization: `Bearer ${this.token}`, accept: "application/json" },
      });
    } catch (cause) {
      throw new SeekritError(`resolve request failed: ${String(cause)}`);
    }
    if (!response.ok) {
      let code = "internal";
      let message = `HTTP ${response.status}`;
      try {
        const body = (await response.json()) as { error?: { code?: string; message?: string } };
        if (body.error?.code) {
          code = body.error.code;
          message = body.error.message ?? message;
        }
      } catch {
        // non-JSON body — keep the fallback
      }
      throw new SeekritApiError(response.status, code, message);
    }
    return (await response.json()) as ResolveResponse;
  }
}
