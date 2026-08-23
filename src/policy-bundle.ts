/**
 * Signed policy bundles (`ap1.`) — verify one before you act on it.
 *
 * A bundle is an allowlist that a publishing admin signed **in the browser**
 * with a P-256 key. The API stores and serves bytes it cannot forge, and every
 * enforcement point verifies the signature against thumbprints pinned in its
 * own deployment config. That is the point of the whole scheme: a secrets
 * manager that cannot read your secrets but *could* rewrite the rule saying
 * which host receives them has moved the vulnerability, not removed it.
 *
 *     ap1.<base64url(canonical JSON body)>.<base64url(ECDSA P-256 signature)>
 *
 * This is the third implementation of the same contract, after
 * `packages/core/src/agent-policy.ts` (which signs) and
 * `crates/seekrit-core/src/policy.rs` (which the proxy verifies with). All
 * three are pinned to `testdata/policy-vectors.json`; change one and regenerate
 * with `apps/proxy/testdata/gen-policy-vectors.mts`.
 *
 * The signature covers the **transported bytes** — the body segment is verified
 * exactly as it arrived — so a canonicalization difference between languages
 * can never become a forged bundle. This file therefore has no canonicalizer:
 * it only ever reads.
 *
 * Fail-closed throughout. An unsigned bundle, a signature that does not check
 * out, a signer that is not pinned, a bundle for another agent, and an expired
 * bundle are all refusals — never a warning and a default.
 */
import { SeekritError } from "./errors.js";
import type { AllowRule } from "./policy.js";

/** Envelope prefix, versioned like every other seekrit blob. */
export const POLICY_PREFIX = "ap1";

/** The bundle schema version this build understands. */
export const POLICY_BUNDLE_VERSION = 1;

/** The four RFC 7638 members of an EC public JWK, and nothing else. */
export interface PolicySignerJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

/** The publishing admin's key, carried inside the signature. */
export interface PolicySigner {
  /** RFC 7638 thumbprint of `jwk` — what a deployment pins. */
  kid: string;
  jwk: PolicySignerJwk;
}

/**
 * One upstream host and what the agent may do to it.
 *
 * Structurally an {@link AllowRule}, because it is the same wire shape: a
 * verified bundle's `rules` can be handed to `seekritFetch` or `seekritEgress`
 * unchanged.
 */
export interface PolicyBundleRule extends AllowRule {
  host: string;
  methods: string[];
  paths: string[];
  allow: string[];
  label?: string;
}

/** The signed body of a policy bundle. */
export interface PolicyBundle {
  v: number;
  /** Organization id — inside the signature, so a bundle cannot be replayed. */
  org: string;
  /** Agent identity id — likewise, so a narrow policy cannot be served broadly. */
  agent: string;
  /** Agent slug, which is what an operator usually writes in config. */
  agent_slug?: string;
  policy_version: number;
  /** Unix seconds. */
  issued_at: number;
  /** Unix seconds. Required: it bounds how long revoked policy keeps working. */
  expires_at: number;
  rules: PolicyBundleRule[];
  signer: PolicySigner;
}

/** A structurally invalid, unverifiable, misdirected, or expired bundle. */
export class SeekritPolicyError extends SeekritError {
  constructor(message: string) {
    super(message);
    this.name = "SeekritPolicyError";
  }
}

// No return annotation on purpose: a bare `Uint8Array` is backed by
// `ArrayBufferLike`, which WebCrypto's `BufferSource` will not accept. Letting
// TypeScript infer the concrete `ArrayBuffer` backing avoids a cast at each use.
function fromBase64url(text: string) {
  const padded = text.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/**
 * RFC 7638 JWK thumbprint (SHA-256, base64url, unpadded) — the identifier a
 * deployment pins, and the one an operator reads off the dashboard.
 */
export async function policySignerThumbprint(jwk: PolicySignerJwk): Promise<string> {
  // Lexicographic member order, no whitespace, per RFC 7638 §3.
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return toBase64url(new Uint8Array(digest));
}

/**
 * Read a bundle **without** verifying its signature — for display only.
 *
 * Named to be hard to misuse. Anything that acts on policy goes through
 * {@link verifyPolicyBundle}.
 */
export function parsePolicyBundleUnverified(envelope: string): PolicyBundle {
  const parts = envelope.trim().split(".");
  if (parts.length !== 3 || parts[0] !== POLICY_PREFIX || parts.some((p) => p.length === 0)) {
    throw new SeekritPolicyError(`not a policy bundle (expected an ${POLICY_PREFIX}. envelope)`);
  }
  let body: PolicyBundle;
  try {
    body = JSON.parse(new TextDecoder().decode(fromBase64url(parts[1] as string))) as PolicyBundle;
  } catch (cause) {
    throw new SeekritPolicyError(`policy bundle body is unreadable: ${String(cause)}`);
  }
  if (body?.v !== POLICY_BUNDLE_VERSION) {
    throw new SeekritPolicyError(`unsupported policy bundle version ${String(body?.v)}`);
  }
  if (!Array.isArray(body.rules) || !body.signer?.jwk) {
    throw new SeekritPolicyError("policy bundle is missing rules or signer");
  }
  return body;
}

/**
 * Verify an envelope's signature and that its signer is one you trust.
 *
 * `pinned` is the trust anchor: thumbprints from **your own deployment config**,
 * never from the API. An empty list is an error rather than "trust anything",
 * because the failure mode of the other choice is silent.
 *
 * Verifying is only half the check — see {@link checkPolicyBundleContext} for
 * the claims that bind a bundle to this deployment and to now.
 */
export async function verifyPolicyBundle(
  envelope: string,
  pinned: string[],
): Promise<PolicyBundle> {
  if (pinned.length === 0) {
    throw new SeekritPolicyError(
      "no policy signers are pinned locally; server policy cannot be trusted",
    );
  }
  const bundle = parsePolicyBundleUnverified(envelope);
  const { jwk, kid } = bundle.signer;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new SeekritPolicyError("policy bundle signer key is not an EC P-256 key");
  }
  // The kid is inside the signature but is derived from the key beside it, so
  // recompute rather than believe it: otherwise a bundle could name a trusted
  // thumbprint while carrying the attacker's key.
  const computed = await policySignerThumbprint(jwk);
  if (computed !== kid) {
    throw new SeekritPolicyError("policy bundle signer kid does not match its key");
  }
  if (!pinned.includes(computed)) {
    throw new SeekritPolicyError(`policy bundle was signed by ${computed}, which is not trusted`);
  }

  const parts = envelope.trim().split(".");
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    fromBase64url(parts[2] as string),
    fromBase64url(parts[1] as string),
  );
  if (!ok) throw new SeekritPolicyError("policy bundle signature is not valid");
  return bundle;
}

export interface PolicyBundleContext {
  /** Reject a bundle for another org. */
  org?: string;
  /** Reject a bundle for another agent. Matches the id or the slug. */
  agent?: string;
  /** Unix seconds. Defaults to now. */
  now?: number;
}

/**
 * Check the claims that bind a bundle to *this* deployment and *now*.
 *
 * Separate from {@link verifyPolicyBundle} because they answer different
 * questions and fail differently: a signature that does not check out is an
 * attack or a bug, while an expired bundle is a republish someone owes you.
 */
export function checkPolicyBundleContext(
  bundle: PolicyBundle,
  context: PolicyBundleContext = {},
): void {
  const now = context.now ?? Math.floor(Date.now() / 1000);
  if (context.org !== undefined && bundle.org !== context.org) {
    throw new SeekritPolicyError(
      `policy bundle is for organization ${bundle.org}, not ${context.org}`,
    );
  }
  if (
    context.agent !== undefined &&
    bundle.agent !== context.agent &&
    bundle.agent_slug !== context.agent
  ) {
    throw new SeekritPolicyError(`policy bundle is for agent ${bundle.agent}, not ${context.agent}`);
  }
  if (now >= bundle.expires_at) {
    throw new SeekritPolicyError(
      `policy bundle expired at ${bundle.expires_at} (now ${now}); republish it`,
    );
  }
}

/**
 * The local, deployment-owned bound on any server-supplied policy: host → the
 * secret names that are *ever* permissible here.
 */
export type PolicyCeiling = Record<string, string[]>;

/**
 * Refuse a bundle that exceeds the local ceiling.
 *
 * Wholesale, not silently intersected — the same choice `RuleSet::check_ceiling`
 * makes in the proxy. A policy that means something narrower than what was
 * published is a policy nobody authored, and running it would make the
 * dashboard lie about what this deployment is doing.
 */
export function checkPolicyCeiling(rules: PolicyBundleRule[], ceiling: PolicyCeiling): void {
  const bound = new Map<string, Set<string>>();
  for (const [host, names] of Object.entries(ceiling)) {
    bound.set(host.trim().toLowerCase(), new Set(names));
  }
  for (const rule of rules) {
    const host = rule.host.trim().toLowerCase();
    const allowed = bound.get(host);
    if (!allowed) {
      throw new SeekritPolicyError(
        `policy names host ${host} which the local ceiling does not permit`,
      );
    }
    for (const name of rule.allow ?? []) {
      if (!allowed.has(name)) {
        throw new SeekritPolicyError(
          `policy would inject ${name} toward ${host} which the local ceiling does not permit`,
        );
      }
    }
  }
}
