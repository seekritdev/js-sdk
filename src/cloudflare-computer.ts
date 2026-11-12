/**
 * Cloudflare Computer adapter — the sandbox holds placeholders, the gateway
 * holds the credentials.
 *
 *     import {
 *       type SeekritEgressGateway,
 *       seekritEgress,
 *       seekritEgressPolicy,
 *       seekritEnv,
 *     } from "@seekrit/sdk/cloudflare-computer";
 *
 *     // Module scope: Workers constructs a WorkerEntrypoint for every call, so a
 *     // gateway built in a class field would resolve on every request.
 *     let egress: SeekritEgressGateway | undefined;
 *
 *     export class SeekritGateway extends WorkerEntrypoint<Env> {
 *       override fetch(request: Request) {
 *         egress ??= seekritEgress({
 *           token: this.env.SEEKRIT_TOKEN,
 *           allow: { "api.openai.com": ["OPENAI_API_KEY"] },
 *         });
 *         return egress.fetch(request, this.ctx);
 *       }
 *     }
 *
 *     // …in the Durable Object that owns the Workspace:
 *     readonly egress = seekritEgressPolicy(this.ctx.exports.SeekritGateway({}), "v1");
 *
 *     // …and the command that runs inside it:
 *     using run = await ws.runtime.exec(
 *       'curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models',
 *       { env: seekritEnv(["OPENAI_API_KEY"]) },
 *     );
 *
 * `$OPENAI_API_KEY` inside the sandbox is the literal string
 * `{{seekrit:OPENAI_API_KEY}}`. The real key is spliced in by
 * {@link seekritEgress}, which runs in *your* Worker — a different isolate,
 * outside the container. Code in the workspace cannot read it, print it, or
 * send it anywhere but the hosts your rules name.
 *
 * **Why this is the strong shape here.** Cloudflare Computer routes every
 * backend's egress — the container's `curl`, the worker shell's `curl`, and
 * `fetch` in the JavaScript isolate — through one `Fetcher` you supply, as
 * already-parsed `Request` objects with the real URL. That is what
 * [`seekrit-proxy`](https://seekrit.dev/docs/guides/agent-proxy) does, minus
 * the parts that make the proxy awkward: no sidecar to run, no `HTTPS_PROXY` to
 * set, and no locally generated CA, because the platform has already terminated
 * TLS by the time the request reaches you. Unlike
 * [`@seekrit/sdk/fetch`](./fetch.ts), the workload cannot bypass it: the
 * gateway is not in the sandbox's address space, and it is the sandbox's only
 * route out.
 *
 * **What it is not.** The rules live in your gateway Worker's own source, which
 * is what makes them trustworthy — the same role `apps/proxy`'s local TOML
 * plays. Rules fetched from an API at runtime would let whoever serves them
 * decide where your credentials go; if you publish signed `ap1.` policy
 * bundles, verify one before you pass its `rules` here.
 *
 * The gateway itself lives in `./egress.ts` and is shared, unchanged, with
 * `@seekrit/sdk/cloudflare-sandbox`; only {@link seekritEgressPolicy} is
 * specific to Cloudflare Computer.
 *
 * Nothing in this file imports `@cloudflare/computer`. Every shape it touches
 * is declared structurally below, so the adapter cannot break on a version bump
 * and `@seekrit/sdk` stays dependency-free.
 */
export * from "./egress.js";

/**
 * Wrap a gateway as a Workspace egress policy.
 *
 * Generic in the gateway so the real `Fetcher` type survives — pass what
 * `ctx.exports.YourGateway({})` gives you.
 *
 * Set `revision` to something that changes when your gateway's behaviour
 * changes. Cloudflare Computer keys its dynamic-worker cache on it, and with no
 * revision it uses a fresh id per call, so every `exec` pays for a cold worker.
 */
export function seekritEgressPolicy<G>(
  gateway: G,
  revision?: string,
): { mode: "http-gateway"; gateway: G; revision?: string } {
  return revision === undefined
    ? { mode: "http-gateway", gateway }
    : { mode: "http-gateway", gateway, revision };
}
