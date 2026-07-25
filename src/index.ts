/**
 * `@seekrit/sdk` — read-path SDK for the zero-knowledge secrets manager.
 *
 * Runs unchanged on Node 18+, Bun, Deno, browsers, and Cloudflare Workers
 * (pure WebCrypto + global `fetch`).
 *
 *     import { Seekrit } from "@seekrit/sdk";
 *     const secrets = await new Seekrit().resolve(); // token from $SEEKRIT_TOKEN
 */
export { Seekrit, DEFAULT_API_URL, type SeekritOptions } from "./client.js";
export {
  TokenKey,
  decryptSecret,
  materialize,
  secretAad,
} from "./crypto.js";
export {
  SeekritError,
  SeekritApiError,
  SeekritCryptoError,
  SeekritReferenceError,
  type CryptoErrorCode,
  type ReferenceErrorCode,
} from "./errors.js";
export { interpolateSecrets, type InterpolationResult } from "./interpolate.js";
export type {
  ResolveResponse,
  ResolveLayer,
  ResolveScope,
  ResolveSecret,
} from "./types.js";
