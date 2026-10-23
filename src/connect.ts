/** Server-side workload client. Enrollment keys sign one-use assertions; they are never sent. */
export type WorkloadConnectOptions = {
  workloadId: string;
  /** HTTPS API origin. Defaults to https://api.seekrit.dev. */
  issuer?: string;
  fetch?: typeof globalThis.fetch;
} & ({ signingKey: CryptoKey | JsonWebKey; getPlatformToken?: never } | {
  /** Return a current JWT from your runtime, with the enrolled audience. Called again at session renewal. */
  getPlatformToken: () => string | Promise<string>; signingKey?: never;
});
export interface GithubTokenScope {
  repositoryIds: number[];
  permissions: Record<string, "read" | "write">;
}
export interface GithubToken extends GithubTokenScope {
  accessToken: string;
  expiresAt: string;
}
export interface ProxyRequest {
  path: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";
  query?: Record<string, string>;
  body?: string;
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const encode = (value: unknown) => base64url(new TextEncoder().encode(JSON.stringify(value)));

/** Generate on the workload/enrolling machine. Register only publicKey with Seekrit. */
export async function createWorkloadKey(): Promise<{ privateKey: JsonWebKey; publicKey: { kty: "EC"; crv: "P-256"; x: string; y: string } }> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const privateKey = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey, publicKey: { kty: "EC", crv: "P-256", x: publicKey.x!, y: publicKey.y! } };
}

export class SeekritConnect {
  private readonly issuer: string;
  private readonly fetcher: typeof globalThis.fetch;
  private key?: Promise<CryptoKey>;
  private session?: { token: string; expiresAt: number };
  private pendingSession?: Promise<string>;

  constructor(private readonly options: WorkloadConnectOptions) {
    if (!!options.signingKey === !!options.getPlatformToken) throw new Error("Choose a signing key or platform token callback");
    const url = new URL(options.issuer ?? "https://api.seekrit.dev");
    if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash || url.username || url.password) {
      throw new Error("Seekrit issuer must be an HTTPS origin");
    }
    this.issuer = url.origin;
    this.fetcher = options.fetch ?? globalThis.fetch;
  }

  private signingKey(): Promise<CryptoKey> {
    if (!this.options.signingKey) throw new Error("This workload uses platform identity");
    this.key ??= "type" in this.options.signingKey
      ? Promise.resolve(this.options.signingKey as CryptoKey)
      : crypto.subtle.importKey("jwk", this.options.signingKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    return this.key;
  }

  private async exchange(): Promise<string> {
    const started = Date.now();
    const now = Math.floor(started / 1000);
    let form: URLSearchParams;
    if (this.options.getPlatformToken) {
      form = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        client_id: this.options.workloadId,
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        subject_token: await this.options.getPlatformToken(), scope: "connect",
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
      });
    } else {
      const unsigned = `${encode({ alg: "ES256", typ: "JWT" })}.${encode({
        iss: this.options.workloadId, sub: this.options.workloadId,
        aud: `${this.issuer}/oauth/token`, iat: now, exp: now + 60, jti: crypto.randomUUID(),
      })}`;
      const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, await this.signingKey(), new TextEncoder().encode(unsigned));
      form = new URLSearchParams({
        grant_type: "client_credentials", client_id: this.options.workloadId,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: `${unsigned}.${base64url(new Uint8Array(signature))}`, scope: "connect",
      });
    }
    const response = await this.fetcher(`${this.issuer}/oauth/token`, {
      method: "POST", redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString(),
    });
    if (!response.ok) throw new Error(`Seekrit workload authentication failed (${response.status})`);
    const result = await response.json() as { access_token: string; expires_in: number; token_type: string };
    if (typeof result.access_token !== "string" || result.token_type !== "Bearer" ||
      !Number.isFinite(result.expires_in) || result.expires_in <= 0 || result.expires_in > 900) {
      throw new Error("Invalid Seekrit workload session response");
    }
    this.session = { token: result.access_token, expiresAt: started + result.expires_in * 1000 };
    return result.access_token;
  }

  private async accessToken(): Promise<string> {
    if (this.session && this.session.expiresAt - Date.now() > 30000) return this.session.token;
    this.pendingSession ??= this.exchange();
    try { return await this.pendingSession; }
    finally { this.pendingSession = undefined; }
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await this.fetcher(`${this.issuer}/v1/connect/${path}`, {
      method: "POST", redirect: "manual",
      headers: { authorization: `Bearer ${await this.accessToken()}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      if (response.status === 401) this.session = undefined;
      // No automatic replay: proxy requests can have side effects.
      throw new Error(`Seekrit Connect request failed (${response.status})`);
    }
    return response.json() as Promise<T>;
  }

  /** GitHub controls the token lifetime; expiresAt is the provider's actual expiry. */
  getToken(connectionId: string, scope: GithubTokenScope): Promise<GithubToken>;
  getToken(connectionId: string, scope: { scopes: string[] }): Promise<{ accessToken: string; expiresAt: string; scopes: string[] }>;
  getToken(connectionId: string, scope: GithubTokenScope | { scopes: string[] }): Promise<GithubToken | { accessToken: string; expiresAt: string; scopes: string[] }> {
    return this.post(`${encodeURIComponent(connectionId)}/token`, scope);
  }

  /** Audience must be explicitly allowed on the enrolled identity. */
  getIdentityToken(audience: string): Promise<{ token: string; expiresIn: number }> {
    return this.post("identity-token", { audience });
  }

  /** Credential injection happens at the broker; no static key is returned. */
  async proxy(connectionId: string, request: ProxyRequest): Promise<Response> {
    const result = await this.post<{ status: number; body: string; contentType: string }>(
      `${encodeURIComponent(connectionId)}/proxy`, request,
    );
    return new Response(result.status === 204 || result.status === 205 || result.status === 304 || request.method === "HEAD" ? null : result.body,
      { status: result.status, headers: { "content-type": result.contentType, "cache-control": "no-store" } });
  }
}
