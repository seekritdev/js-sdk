/**
 * Placeholder substitution — the in-process twin of `apps/proxy/src/substitute.rs`.
 *
 * Scans text for `{{seekrit:NAME}}` and replaces each occurrence with a
 * looked-up value. It is **fail-closed**: a placeholder naming a secret that is
 * not permitted toward this upstream, or one that does not resolve, throws
 * rather than forwarding the placeholder (or, worse, letting the wrong host
 * receive a real credential). Errors carry the *name* only — never the value.
 *
 * This is a different feature from {@link interpolateSecrets}, which expands
 * `${OTHER_SECRET}` references *between stored secrets*. Two syntaxes, two
 * engines: `${…}` is about how a secret's value is composed, `{{seekrit:…}}` is
 * about where a value is injected on the way out.
 *
 * The rules are pinned by the shared golden fixture (`testdata/vectors.json`,
 * `substitution`), which the Rust proxy asserts against the same file.
 */
import { SeekritError, SeekritSubstitutionError } from "./errors.js";

const OPEN = "{{seekrit:";
const CLOSE = "}}";

/** The result of looking up one placeholder name for one outbound request. */
export type Lookup =
  | { kind: "value"; value: string }
  /** Referenced but not permitted toward this upstream (default-deny). */
  | { kind: "denied"; reason?: string }
  /** Permitted, but no such secret resolved (fail-closed). */
  | { kind: "unknown" };

/** A completed pass: the rewritten text and the names that were injected. */
export interface SubstitutionOutcome {
  text: string;
  /** Sorted, deduplicated. Names only — safe to log. */
  names: string[];
}

/** Placeholder names are env-var style: `[A-Za-z0-9_]+`. */
function isValidName(name: string): boolean {
  return name.length > 0 && /^[A-Za-z0-9_]+$/.test(name);
}

/**
 * Replace every `{{seekrit:NAME}}` in `input` using `lookup`. A malformed or
 * unterminated marker is left verbatim — it is not a valid placeholder, so it
 * is not a credential reference either.
 *
 * @throws {SeekritSubstitutionError} on a denied or unresolved name.
 */
export function substitute(input: string, lookup: (name: string) => Lookup): SubstitutionOutcome {
  const names = new Set<string>();
  let out = "";
  let i = 0;

  while (i < input.length) {
    const at = input.indexOf(OPEN, i);
    if (at === -1) {
      out += input.slice(i);
      break;
    }
    out += input.slice(i, at);

    const after = at + OPEN.length;
    const close = input.indexOf(CLOSE, after);
    if (close === -1) {
      // No closing marker anywhere: the remainder is literal.
      out += input.slice(at);
      break;
    }

    const name = input.slice(after, close);
    if (!isValidName(name)) {
      // Not a placeholder. Emit the opener and rescan from just after it, so a
      // nested `{{seekrit:` inside the junk is still found.
      out += OPEN;
      i = after;
      continue;
    }

    const found = lookup(name);
    if (found.kind === "denied") {
      throw new SeekritSubstitutionError("denied", name, found.reason);
    }
    if (found.kind === "unknown") {
      throw new SeekritSubstitutionError("unresolved", name);
    }
    out += found.value;
    names.add(name);
    i = close + CLOSE.length;
  }

  return { text: out, names: [...names].sort() };
}

/**
 * Substitute inside one request header's value — {@link substitute}, plus the
 * one place a client encodes a placeholder before sending it.
 *
 * git over HTTPS (and anything else speaking HTTP Basic) sends `user:password`
 * base64-encoded, so `https://x-access-token:{{seekrit:GITHUB_TOKEN}}@github.com`
 * leaves the client as `Authorization: Basic eC1hY2Nlc3Mt…` and the marker is
 * invisible to a text scan. For exactly that shape — an `Authorization` or
 * `Proxy-Authorization` value of `Basic` (any case), one or more spaces, then
 * canonical padded base64 that decodes to UTF-8 — the decoded text goes through
 * the same `lookup` and is re-encoded, keeping the scheme and spacing as sent.
 * A denied or unknown name throws exactly as it does anywhere else.
 *
 * Every other value, a Basic credential failing any of those checks included,
 * is substituted as plain text — so `Basic {{seekrit:GIT_BASIC}}` still works,
 * and no other header or scheme is ever base64-decoded. Pinned, like the rest,
 * by the `header` cases of the shared vectors (`apps/proxy/src/substitute.rs`
 * is the reference).
 *
 * @throws {SeekritSubstitutionError} on a denied or unresolved name.
 */
export function substituteHeader(
  name: string,
  value: string,
  lookup: (name: string) => Lookup,
): SubstitutionOutcome {
  const basic = basicCredential(name, value);
  if (basic === undefined) return substitute(value, lookup);
  const inner = substitute(basic.decoded, lookup);
  // Nothing injected: forward the credential exactly as it arrived.
  if (inner.names.length === 0) return { text: value, names: [] };
  return { text: basic.prefix + encodeBase64(new TextEncoder().encode(inner.text)), names: inner.names };
}

/**
 * Whether one request header's value carries a placeholder
 * {@link substituteHeader} would act on — {@link hasPlaceholder}, seeing inside
 * a Basic credential the same way.
 */
export function headerHasPlaceholder(name: string, value: string): boolean {
  const basic = basicCredential(name, value);
  return hasPlaceholder(basic === undefined ? value : basic.decoded);
}

const CREDENTIAL_HEADERS = new Set(["authorization", "proxy-authorization"]);
/** `Basic`, any case, then one or more spaces. ASCII only: `i` without `u` never folds non-ASCII to ASCII. */
const BASIC_PREFIX = /^basic +/i;
/** Standard alphabet (RFC 4648 §4), padded. The length and padding bits are checked by re-encoding. */
const BASE64_SHAPE = /^[A-Za-z0-9+/]+={0,2}$/;

/** The scheme-and-spaces prefix and decoded text of a Basic credential, or `undefined` to scan as text. */
function basicCredential(name: string, value: string): { prefix: string; decoded: string } | undefined {
  if (!CREDENTIAL_HEADERS.has(name.toLowerCase())) return undefined;
  const prefix = BASIC_PREFIX.exec(value)?.[0];
  if (prefix === undefined) return undefined;
  const bytes = decodeCanonicalBase64(value.slice(prefix.length));
  if (bytes === undefined) return undefined;
  try {
    return { prefix, decoded: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch {
    return undefined;
  }
}

/**
 * Decode standard base64 only if `input` is the *canonical* encoding of its
 * bytes: non-empty, padded to a multiple of four, standard alphabet, zero
 * padding bits. `atob` alone is lenient (it drops whitespace and accepts a
 * missing pad), and every leniency is a different answer to "is this a
 * credential?" than the proxy gives — so the re-encode must reproduce `input`.
 */
function decodeCanonicalBase64(input: string): Uint8Array | undefined {
  if (input.length % 4 !== 0 || !BASE64_SHAPE.test(input)) return undefined;
  let binary: string;
  try {
    binary = atob(input);
  } catch {
    return undefined;
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return encodeBase64(bytes) === input ? bytes : undefined;
}

/** Standard base64 with `=` padding. */
function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Build the placeholder for a secret name: `placeholder("OPENAI_API_KEY")` is
 * `"{{seekrit:OPENAI_API_KEY}}"`. One place that knows the syntax, and it
 * rejects a name the engine would not recognise rather than silently emitting
 * text that gets forwarded to the upstream as-is.
 */
export function placeholder(name: string): string {
  if (!isValidName(name)) {
    throw new SeekritError(
      `${JSON.stringify(name)} is not a usable secret name: use [A-Za-z0-9_]+`,
    );
  }
  return `${OPEN}${name}${CLOSE}`;
}

/** Whether `text` contains at least one syntactically valid placeholder. */
export function hasPlaceholder(text: string): boolean {
  let i = 0;
  for (;;) {
    const at = text.indexOf(OPEN, i);
    if (at === -1) return false;
    const after = at + OPEN.length;
    const close = text.indexOf(CLOSE, after);
    if (close === -1) return false;
    if (isValidName(text.slice(after, close))) return true;
    i = after;
  }
}
