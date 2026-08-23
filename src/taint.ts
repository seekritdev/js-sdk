/**
 * React's taint API, applied to a resolved set of secrets.
 *
 * `experimental_taintUniqueValue` and `experimental_taintObjectReference` are how
 * React is told that a value must never be serialized to the client: pass one to
 * a client component afterwards and the render throws instead of shipping it.
 * That is the difference between a convention and a failing build, and it is the
 * main reason `@seekrit/sdk/react` exists rather than a note in the docs saying
 * "resolve in a server component".
 *
 * The API is taken as an argument rather than imported, because it is absent
 * from stable React (Next.js needs `experimental: { taint: true }`, which swaps
 * in a React build that has it) and because a pure function is testable without
 * a renderer.
 */
import { SeekritError } from "./errors.js";

/** The two React functions this needs, either of which may be missing. */
export interface TaintApi {
  taintObject?: (message: string, object: object) => void;
  taintValue?: (message: string, lifetime: object, value: string) => void;
}

export const OBJECT_TAINT_MESSAGE =
  "A seekrit secret map cannot be passed to the client. Read the values you need in a server " +
  "component and pass only the non-secret result.";

export function valueTaintMessage(name: string): string {
  return (
    `The value of the seekrit secret ${name} cannot be passed to the client. Use it on the ` +
    `server, or hold the placeholder {{seekrit:${name}}} on the client and substitute it in a ` +
    "route handler (@seekrit/sdk/route)."
  );
}

export const NO_TAINT_WARNING =
  "[seekrit] React's taint API is unavailable, so a secret passed to a client component will be " +
  "serialized rather than refused. In Next.js, set `experimental: { taint: true }`.";

export function noTaintError(): SeekritError {
  return new SeekritError(
    'taint: "require" was asked for, but this React build exposes no taint API. Enable it (in ' +
      "Next.js: `experimental: { taint: true }`) or set taint: false to accept that a secret " +
      "passed to a client component will be serialized rather than refused.",
  );
}

let warned = false;

/**
 * Taint a resolved set: the map by reference, then each value individually.
 *
 * `values` is the lifetime object for the per-value taints, which is exactly
 * right — React keeps a value tainted for as long as the object it was tainted
 * against is reachable, and the map is reachable for as long as the render's
 * cache entry holds it.
 *
 * @param required throw when the API is unavailable instead of warning once.
 */
export function protectValues(
  values: Record<string, string>,
  api: TaintApi,
  required = false,
): void {
  if (!api.taintObject && !api.taintValue) {
    if (required) throw noTaintError();
    if (!warned) {
      warned = true;
      console.warn(NO_TAINT_WARNING);
    }
    return;
  }

  api.taintObject?.(OBJECT_TAINT_MESSAGE, values);
  if (!api.taintValue) return;
  for (const name of Object.keys(values)) {
    try {
      api.taintValue(valueTaintMessage(name), values, values[name]);
    } catch {
      // React declines to taint some values — a very short string, for one,
      // because a value that collides with ordinary text would poison unrelated
      // props. Its refusal is not ours to surface, and the map-level taint above
      // still covers passing the whole set across.
    }
  }
}

/** Test seam: forget that the warning has been emitted. */
export function resetTaintWarning(): void {
  warned = false;
}
