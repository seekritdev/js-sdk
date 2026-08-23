/**
 * How a refusal looks on the wire — one wording, every injection surface.
 *
 * `apps/proxy` answers a refused request with a **403** whose body names the
 * placeholder or the constraint that refused. The in-process shim and the
 * Cloudflare Computer egress gateway answer with the same status, the same
 * body, and the same machine-checkable headers, so moving a workload from one
 * to another does not change its error handling. The Rust originals are
 * `Reject::into_response` and `describe_operation` in `apps/proxy/src/proxy.rs`.
 *
 * Names only, never values — a refusal is a thing you log.
 */
import type { SeekritSubstitutionError } from "./errors.js";
import type { PolicyDecision } from "./policy.js";

/** Why an *operation* was refused, in the proxy's words. */
export function describeOperation(decision: PolicyDecision): string {
  switch (decision) {
    case "allow":
      return "permitted";
    case "no_rule":
      return "no policy rule covers this upstream";
    case "method_not_allowed":
      return "this method is not permitted toward this upstream";
    case "path_not_allowed":
      return "this path is not permitted toward this upstream";
    case "secret_not_allowed":
      return "that secret is not permitted toward this upstream";
  }
}

/** Why a *placeholder* was refused, in the proxy's words. */
export function refusalBody(error: SeekritSubstitutionError): string {
  return error.code === "denied"
    ? `placeholder {{seekrit:${error.secretName}}} is not allowed toward this upstream`
    : `placeholder {{seekrit:${error.secretName}}} references a secret that is not available`;
}

/** A 403 a caller can tell apart from an upstream 403. */
export function refusalResponse(error: SeekritSubstitutionError): Response {
  return new Response(refusalBody(error), {
    status: 403,
    statusText: "Forbidden",
    headers: {
      "content-type": "text/plain; charset=utf-8",
      // Machine-checkable, so a caller can tell our refusal from an upstream 403.
      "x-seekrit-refusal": error.code,
      "x-seekrit-secret": error.secretName,
    },
  });
}
