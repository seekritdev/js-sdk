export type CryptoErrorCode =
  | "DECRYPT_FAILED"
  | "MALFORMED_BLOB"
  | "UNSUPPORTED_VERSION"
  | "MALFORMED_TOKEN";

/** Base class for every error thrown by the SDK. */
export class SeekritError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SeekritError";
  }
}

/**
 * A token, wrapped DEK, or secret ciphertext could not be parsed or decrypted.
 * Deliberately unspecific: a decrypt failure does not distinguish "wrong key"
 * from "tampered data" from "mismatched context".
 */
export class SeekritCryptoError extends SeekritError {
  readonly code: CryptoErrorCode;
  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.name = "SeekritCryptoError";
    this.code = code;
  }
}

/** Why a `${OTHER_SECRET}` reference could not be expanded. */
export type ReferenceErrorCode = "CYCLE" | "TOO_LARGE";

/**
 * A secret references another secret in a way that has no answer: a cycle, or
 * an expansion that grows without bound. An unknown reference is *not* an error
 * — it is left as literal text (see `interpolateSecrets`).
 */
export class SeekritReferenceError extends SeekritError {
  readonly code: ReferenceErrorCode;
  constructor(code: ReferenceErrorCode, message: string) {
    super(message);
    this.name = "SeekritReferenceError";
    this.code = code;
  }
}

/** The resolve API returned a non-2xx response. */
export class SeekritApiError extends SeekritError {
  readonly status: number;
  /** `error.code` from the API body, or `"internal"` if the body did not parse. */
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(`${status} ${code}: ${message}`);
    this.name = "SeekritApiError";
    this.status = status;
    this.code = code;
  }
}

/** Why a `{{seekrit:NAME}}` placeholder could not be substituted. */
export type SubstitutionErrorCode =
  /** The allowlist does not permit this name toward this upstream. */
  | "denied"
  /** Permitted, but the token resolved no secret by that name. */
  | "unresolved";

/**
 * A placeholder could not be substituted, so the request was not sent.
 *
 * Both cases are fail-closed on purpose: forwarding the literal placeholder
 * would leak an internal name to the upstream, and substituting anyway would
 * hand a credential to a host that is not allowed to have it. Carries the
 * secret's *name* — never its value.
 */
export class SeekritSubstitutionError extends SeekritError {
  readonly code: SubstitutionErrorCode;
  /** The placeholder name that failed. Safe to log. */
  readonly secretName: string;
  constructor(code: SubstitutionErrorCode, secretName: string, detail?: string) {
    super(
      code === "denied"
        ? `secret ${secretName} is not allowed toward this upstream${detail ? ` (${detail})` : ""}`
        : `secret ${secretName} is allowed but did not resolve`,
    );
    this.name = "SeekritSubstitutionError";
    this.code = code;
    this.secretName = secretName;
  }
}
