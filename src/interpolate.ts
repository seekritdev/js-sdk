/**
 * Secret references: `${OTHER_SECRET}` inside a secret value.
 *
 * Expansion happens here, on the client, after the layers are merged — the API
 * only ever holds the ciphertext of the literal `${OTHER_SECRET}` text. The
 * rules are fixed by the shared golden fixture (`testdata/vectors.json`,
 * `interpolation`), which every seekrit client is tested against:
 *
 * - `${NAME}` becomes `NAME`'s value from the same merged set, recursively.
 * - `NAME` must look like an environment variable (`[A-Za-z_][A-Za-z0-9_]*`);
 *   anything else (`${FOO:-bar}`, `${1}`) is left exactly as written.
 * - A name that is not in the set is left literal and listed in `unresolved`,
 *   so a stored value containing e.g. `${GITHUB_SHA}` keeps working.
 * - `$${NAME}` is an escape for the literal text `${NAME}`.
 * - A reference cycle throws {@link SeekritReferenceError}.
 */
import { SeekritReferenceError } from "./errors.js";

const REFERENCE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Cap on a single expanded value: nested references can multiply length. */
const MAX_EXPANDED_LENGTH = 1_048_576;

type Segment = { literal: string } | { reference: string; raw: string };

/** The single tokenizer the rules above are expressed in terms of. */
function* scan(text: string): Generator<Segment> {
  let i = 0;
  while (i < text.length) {
    const dollar = text.indexOf("$", i);
    if (dollar === -1) {
      yield { literal: text.slice(i) };
      return;
    }
    if (dollar > i) yield { literal: text.slice(i, dollar) };

    if (text[dollar + 1] === "$" && text[dollar + 2] === "{") {
      yield { literal: "${" };
      i = dollar + 3;
      continue;
    }

    const close = text[dollar + 1] === "{" ? text.indexOf("}", dollar + 2) : -1;
    const reference = close === -1 ? null : text.slice(dollar + 2, close);
    if (reference !== null && REFERENCE_NAME.test(reference)) {
      yield { reference, raw: text.slice(dollar, close + 1) };
      i = close + 1;
      continue;
    }

    yield { literal: "$" };
    i = dollar + 1;
  }
}

export interface InterpolationResult {
  /** The variable set with every reference expanded. */
  values: Record<string, string>;
  /** Names whose value had at least one reference expanded. */
  expanded: string[];
  /** Referenced names that exist nowhere in the set, deduped and sorted. */
  unresolved: string[];
}

/**
 * Expand `${NAME}` references throughout a merged variable set. Pure — the
 * input is never mutated. Throws {@link SeekritReferenceError} on a cycle.
 */
export function interpolateSecrets(values: Record<string, string>): InterpolationResult {
  const resolved = new Map<string, string>();
  const unresolved = new Set<string>();
  const expanded: string[] = [];
  const stack: string[] = [];

  function resolve(name: string): string {
    const cached = resolved.get(name);
    if (cached !== undefined) return cached;

    const cycleAt = stack.indexOf(name);
    if (cycleAt !== -1) {
      const chain = [...stack.slice(cycleAt), name];
      throw new SeekritReferenceError("CYCLE", `secret reference cycle: ${chain.join(" -> ")}`);
    }

    stack.push(name);
    let out = "";
    for (const segment of scan(values[name] as string)) {
      if ("literal" in segment) {
        out += segment.literal;
      } else if (Object.prototype.hasOwnProperty.call(values, segment.reference)) {
        out += resolve(segment.reference);
      } else {
        unresolved.add(segment.reference);
        out += segment.raw;
      }
    }
    stack.pop();

    if (out.length > MAX_EXPANDED_LENGTH) {
      throw new SeekritReferenceError(
        "TOO_LARGE",
        `${name} expands to more than ${MAX_EXPANDED_LENGTH} bytes`,
      );
    }
    resolved.set(name, out);
    return out;
  }

  const result: Record<string, string> = {};
  for (const name of Object.keys(values)) {
    const value = resolve(name);
    result[name] = value;
    if (value !== values[name]) expanded.push(name);
  }

  return { values: result, expanded, unresolved: [...unresolved].sort() };
}
