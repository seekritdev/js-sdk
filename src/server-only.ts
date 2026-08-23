/**
 * The guard on the server-only entrypoints.
 *
 * `@seekrit/sdk/react` and `@seekrit/sdk/route` hold a `skt_` service token, and
 * a service token in a client bundle is a published credential — not a leak that
 * needs a mistake on top of it, just a `view-source` away. So both refuse to
 * load in a browser rather than working and being wrong.
 *
 * This is the second of two layers. The first is the `"browser"` export
 * condition in `package.json`, which hands a bundler a module that throws at
 * import time, so a `use client` file importing one of these fails at build.
 * This one catches the runtimes and bundlers that do not honour that condition,
 * at the cost of failing a little later.
 */
import { SeekritError } from "./errors.js";

/** The error both layers raise, so a build failure and a runtime one read alike. */
export function serverOnlyError(subpath: string): SeekritError {
  return new SeekritError(
    `@seekrit/sdk/${subpath} is server-only and was loaded in a client bundle. It holds a ` +
      "service token, which must never reach the browser. Read secrets in a server component " +
      "(@seekrit/sdk/react) and pass only the non-secret result, or hold a {{seekrit:NAME}} " +
      "placeholder on the client and substitute it in a route handler (@seekrit/sdk/route).",
  );
}

/** Throw if this looks like a browser. Called at module scope by the callers. */
export function assertServerOnly(subpath: string): void {
  const global = globalThis as { window?: unknown; document?: unknown };
  if (typeof global.window === "undefined" || typeof global.document === "undefined") return;
  throw serverOnlyError(subpath);
}
