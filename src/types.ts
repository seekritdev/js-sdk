/** The JSON shape of `GET /v1/resolve` for a service-token caller. */

export interface ResolveScope {
  orgId: string;
  orgSlug: string;
  appId: string;
  appSlug: string;
  envId: string;
  envSlug: string;
}

export interface ResolveSecret {
  name: string;
  ciphertext: string;
}

export interface ResolveLayer {
  /** `"group"` (a composed group) or `"app"` (the app environment). */
  source: "group" | "app";
  environmentId: string;
  slug: string;
  groupSlug?: string;
  /** `wd1.` blob — the DEK wrapped to the caller's public key. */
  wrappedDek: string;
  secrets: ResolveSecret[];
}

export interface ResolveResponse {
  scope: ResolveScope;
  /** Lowest precedence first: composed groups, then the app environment. */
  layers: ResolveLayer[];
}
