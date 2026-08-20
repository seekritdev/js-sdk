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
import { SeekritSubstitutionError } from "./errors.js";

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
