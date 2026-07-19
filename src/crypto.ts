/**
 * Zero-knowledge read path, byte-compatible with `@seekrit/crypto` and
 * `crates/seekrit-core`. Pure WebCrypto — no runtime built-ins — so it runs
 * unchanged on Node, Bun, Deno, browsers, and Cloudflare Workers.
 *
 * Blob formats (all segments base64url, no padding):
 *   token       skt_<id>_<pkcs8 private key>
 *   wrapped DEK wd1.<ephemeral pub (raw SEC1)>.<hkdf salt>.<iv>.<ciphertext||tag>
 *   secret      sc1.<iv>.<ciphertext||tag>
 */
import { SeekritCryptoError } from "./errors.js";
import type { ResolveResponse } from "./types.js";

const HKDF_INFO = "seekrit/wrap-dek/v1";
// Only the first two underscores are separators; the key segment may contain "_".
const TOKEN_RE = /^(skt_[0-9A-Za-z]+)_([A-Za-z0-9_-]+)$/;

function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function fromBase64Url(text: string): Uint8Array {
  const base64 = text.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function splitBlob(blob: string, prefix: string, segments: number): string[] {
  const parts = blob.split(".");
  if (parts[0] !== prefix) {
    throw new SeekritCryptoError(
      "UNSUPPORTED_VERSION",
      `expected a "${prefix}" blob, got "${parts[0] ?? ""}"`,
    );
  }
  if (parts.length !== segments + 1 || parts.some((p) => p.length === 0)) {
    throw new SeekritCryptoError("MALFORMED_BLOB", `malformed "${prefix}" blob`);
  }
  return parts.slice(1);
}

/** AAD binding a secret ciphertext to its environment and name. */
export function secretAad(environmentId: string, name: string): string {
  return `${environmentId}/${name}`;
}

async function deriveWrappingKey(
  ownPrivateKey: CryptoKey,
  peerPublicKey: CryptoKey,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const ecdh = { name: "ECDH", public: peerPublicKey } as unknown as EcdhKeyDeriveParams;
  const sharedBits = await crypto.subtle.deriveBits(ecdh, ownPrivateKey, 256);
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: utf8Encode(HKDF_INFO) as BufferSource,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

/** The P-256 private key recovered from a `skt_...` service token. */
export class TokenKey {
  private constructor(
    readonly tokenId: string,
    private readonly privateKey: CryptoKey,
  ) {}

  static async parse(token: string): Promise<TokenKey> {
    const match = TOKEN_RE.exec(token);
    if (!match) {
      throw new SeekritCryptoError("MALFORMED_TOKEN", "not a valid seekrit service token");
    }
    const [, tokenId, keyB64] = match as unknown as [string, string, string];
    try {
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        fromBase64Url(keyB64) as BufferSource,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      );
      return new TokenKey(tokenId, privateKey);
    } catch {
      throw new SeekritCryptoError("MALFORMED_TOKEN", "service token private key is corrupted");
    }
  }

  /** Recover a 32-byte environment DEK from a `wd1.` blob. */
  async unwrapDek(wrapped: string): Promise<Uint8Array> {
    const [ephB64, saltB64, ivB64, ctB64] = splitBlob(wrapped, "wd1", 4);
    const ephemeralKey = await crypto.subtle.importKey(
      "raw",
      fromBase64Url(ephB64) as BufferSource,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const wrappingKey = await deriveWrappingKey(
      this.privateKey,
      ephemeralKey,
      fromBase64Url(saltB64),
    );
    try {
      const dek = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64Url(ivB64) as BufferSource },
        wrappingKey,
        fromBase64Url(ctB64) as BufferSource,
      );
      return new Uint8Array(dek);
    } catch {
      throw new SeekritCryptoError(
        "DECRYPT_FAILED",
        "DEK unwrap failed: wrong private key or tampered grant",
      );
    }
  }
}

/** Decrypt an `sc1.` secret ciphertext to its UTF-8 plaintext. */
export async function decryptSecret(dek: Uint8Array, blob: string, aad: string): Promise<string> {
  const [ivB64, ctB64] = splitBlob(blob, "sc1", 2);
  const key = await crypto.subtle.importKey("raw", dek as BufferSource, { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64Url(ivB64) as BufferSource,
        additionalData: utf8Encode(aad) as BufferSource,
      },
      key,
      fromBase64Url(ctB64) as BufferSource,
    );
    return utf8Decode(new Uint8Array(plaintext));
  } catch {
    throw new SeekritCryptoError(
      "DECRYPT_FAILED",
      "secret decryption failed: wrong key, tampered data, or mismatched context",
    );
  }
}

/**
 * Decrypt every layer and merge by precedence. Layers arrive lowest precedence
 * first (composed groups, then the app environment); later layers overwrite
 * earlier ones on a name collision.
 */
export async function materialize(
  response: ResolveResponse,
  key: TokenKey,
): Promise<Record<string, string>> {
  const merged: Record<string, string> = {};
  for (const layer of response.layers) {
    const dek = await key.unwrapDek(layer.wrappedDek);
    for (const secret of layer.secrets) {
      merged[secret.name] = await decryptSecret(
        dek,
        secret.ciphertext,
        secretAad(layer.environmentId, secret.name),
      );
    }
  }
  return merged;
}
