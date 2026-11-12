/**
 * Cloudflare Sandbox adapter — the container holds placeholders, an outbound
 * handler in your Worker holds the credentials.
 *
 *     import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
 *     import {
 *       containerTrustEnv,
 *       type SeekritEgressGateway,
 *       seekritEgress,
 *       seekritEnv,
 *     } from "@seekrit/sdk/cloudflare-sandbox";
 *
 *     // Module scope: Workers constructs a WorkerEntrypoint for every call, so a
 *     // gateway built in a class field would resolve on every request.
 *     let egress: SeekritEgressGateway | undefined;
 *
 *     export class Outbound extends WorkerEntrypoint<Env> {
 *       override fetch(request: Request) {
 *         egress ??= seekritEgress({
 *           token: this.env.SEEKRIT_TOKEN,
 *           allow: { "api.openai.com": ["OPENAI_API_KEY"] },
 *         });
 *         return egress.fetch(request, this.ctx);
 *       }
 *     }
 *
 *     // …in the Durable Object that owns the container, before start():
 *     await container.interceptOutboundHttps("*", this.ctx.exports.Outbound);
 *     container.start({ image: container.images.agent, enableInternet: false });
 *
 *     // …and the command that runs inside it:
 *     await container.exec(["python", "agent.py"], {
 *       env: { ...seekritEnv(["OPENAI_API_KEY"]), ...containerTrustEnv() },
 *     });
 *
 * `$OPENAI_API_KEY` inside the container is the literal string
 * `{{seekrit:OPENAI_API_KEY}}`. The real key is spliced in by
 * {@link seekritEgress}, which runs in *your* Worker — outside the container,
 * after the platform has terminated its TLS. Code in the container cannot read
 * the key, print it, or send it anywhere but the hosts your rules name.
 *
 * **Why `"*"` and not a list of hosts.** Intercepting every HTTPS host makes the
 * gateway the container's only route out, so its default-deny is the egress
 * policy: a host no rule names is answered 403 by the gateway, with the reason,
 * rather than resolved by DNS. With `enableInternet: false` there is no other
 * path for a request to take.
 *
 * This is the same gateway `@seekrit/sdk/cloudflare-computer` exports — shared
 * code in `./egress.ts`, so the two cannot disagree about what is let through.
 * Nothing here imports `@cloudflare/sandbox` or `cloudflare:workers`, so the
 * adapter cannot break on a version bump and `@seekrit/sdk` stays
 * dependency-free.
 */
export * from "./egress.js";

/**
 * Where Cloudflare Containers writes the CA it terminates intercepted HTTPS
 * with. It exists only while an HTTPS intercept is registered, and is created
 * per container — never bake it into an image.
 */
export const CONTAINERS_CA_PATH = "/etc/cloudflare/certs/cloudflare-containers-ca.crt";

/**
 * Environment that makes common clients trust the intercepting CA.
 *
 *     await container.exec(["git", "clone", url], { env: containerTrustEnv() });
 *
 * Every TLS client in the container has to accept the certificate the platform
 * presents in place of the real host's, or every intercepted request fails its
 * handshake before the gateway sees it. Node and Bun add the CA to their
 * built-in roots (`NODE_EXTRA_CA_CERTS`); OpenSSL, curl, git, and Python
 * `requests` instead *replace* their trust store with the file named. That is
 * correct only when every HTTPS host is intercepted — `interceptOutboundHttps("*", …)`
 * — because a host that is not would be checked against this CA alone and
 * fail. Intercept `"*"`, or pick the variables you need yourself.
 *
 * The alternative is installing the CA into the image's system store from the
 * container's entrypoint, which is what Cloudflare's docs describe for images
 * you control. These variables work without touching the image.
 */
export function containerTrustEnv(path: string = CONTAINERS_CA_PATH): Record<string, string> {
  return {
    NODE_EXTRA_CA_CERTS: path,
    SSL_CERT_FILE: path,
    CURL_CA_BUNDLE: path,
    GIT_SSL_CAINFO: path,
    REQUESTS_CA_BUNDLE: path,
  };
}
