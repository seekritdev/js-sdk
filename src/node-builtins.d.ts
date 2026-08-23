/**
 * The sliver of Node's `child_process` the Vite plugin uses, declared here so
 * the package keeps `"types": []` — no `@types/node`, no Node globals in scope
 * for the modules that must stay browser- and Worker-safe.
 *
 * `.d.ts` inputs are not emitted, so nothing about this reaches `dist/` or a
 * consumer's type-check.
 */
declare module "node:child_process" {
  interface StdoutLike {
    setEncoding(encoding: string): void;
    on(event: "data", listener: (chunk: string) => void): void;
  }

  interface ChildProcessLike {
    stdout: StdoutLike | null;
    on(event: "error", listener: (error: { code?: string; message: string }) => void): void;
    on(event: "close", listener: (code: number | null) => void): void;
  }

  export function spawn(
    command: string,
    args: readonly string[],
    options: { stdio: Array<"inherit" | "pipe" | "ignore">; env?: Record<string, string | undefined> },
  ): ChildProcessLike;
}
