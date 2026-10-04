# seekrit — JavaScript / TypeScript SDK

Read-path SDK for [seekrit](https://seekrit.dev). Authenticate with a service
token, resolve your environment, and get **decrypted** secrets — the API only
ever returns ciphertext; decryption happens in your process.

Pure **WebCrypto** + global `fetch`, so it runs unchanged on **Node 18+, Bun,
Deno, browsers, and Cloudflare Workers** — no Node built-ins, no polyfills.

> This repo is a **read-only mirror** published from seekrit's monorepo so the
> code that holds your token and decrypts plaintext is auditable. Don't commit
> here — it's overwritten on each sync. Issues and PRs welcome.

## Install

```sh
npm install @seekrit/sdk      # or: pnpm add / yarn add / bun add
```

Deno:

```ts
import { Seekrit } from "npm:@seekrit/sdk";
```

## Usage

```ts
import { Seekrit } from "@seekrit/sdk";

const client = new Seekrit();          // token from $SEEKRIT_TOKEN
const secrets = await client.resolve(); // { DATABASE_URL: "postgres://…", … }

const dbUrl = await client.get("DATABASE_URL");
```

### Cloudflare Workers

There's no ambient environment, so pass the token from your Worker's env:

```ts
export default {
  async fetch(request, env) {
    const client = new Seekrit({ token: env.SEEKRIT_TOKEN });
    const { API_KEY } = await client.resolve();
    // ...
  },
};
```

### Options

```ts
new Seekrit({
  token: "skt_…",                       // default: $SEEKRIT_TOKEN
  apiUrl: "https://api.seekrit.dev",    // default: $SEEKRIT_API_URL or hosted
  with: { shared: "dev" },              // ?with= override for a composed group
  fetch: customFetch,                   // default: globalThis.fetch
});
```

A service token binds to a single app environment (plus its composed group
slices). `with` pulls a different environment slice of a composed group.

### Errors

- `SeekritApiError` — non-2xx from the API; has `.status` and `.code`
  (`"unauthorized"`, `"forbidden"`, `"not_found"`, …).
- `SeekritCryptoError` — a token or ciphertext could not be parsed/decrypted.
- `SeekritError` — base class (also covers network failures).

`resolve()` is **fail-closed**: it rejects rather than returning partial results.

## Hold a placeholder instead of a key

`@seekrit/sdk/fetch` substitutes `{{seekrit:NAME}}` placeholders into outbound
requests, so a provider key is never in your source, your `.env`, or
`process.env`:

```ts
import { createOpenAI } from "@ai-sdk/openai";
import { seekritFetch } from "@seekrit/sdk/fetch";

const openai = createOpenAI({
  apiKey: "{{seekrit:OPENAI_API_KEY}}",
  fetch: seekritFetch({ allow: { "api.openai.com": ["OPENAI_API_KEY"] } }),
});
```

The allowlist is the boundary, and it is default-deny: a name that is not
permitted toward that host, method, and path is refused, and so is a name that
did not resolve. Neither sends the request.

A refusal answers with the same **403** the proxy answers with, carrying
`x-seekrit-refusal` and the secret's name but never its value. That is on
purpose: a provider SDK wraps anything its HTTP layer raises into an opaque
connection error *and retries it*, so raising would turn a denied placeholder
into "Connection error" after six attempts. Ask for `refusal: "throw"` to get the typed
error instead.

Because it runs in your process, this is a weaker boundary than the
[egress proxy](https://seekrit.dev/docs/guides/agent-proxy) — the same
placeholder, substituted in a separate process. What it does buy: the value
exists only inside one HTTP call, so it never reaches model context, a tool
result, or a trace exporter. Full trade-off:
<https://seekrit.dev/docs/guides/agent-proxy/in-process>.

### Mastra

`@seekrit/sdk/mastra` returns the function form of Mastra's `model`, so each
request can resolve its own tenant's credentials without rebuilding the model:

```ts
import { createOpenAI } from "@ai-sdk/openai";
import { seekritModel } from "@seekrit/sdk/mastra";

model: seekritModel(
  ({ apiKey, fetch }) => createOpenAI({ apiKey, fetch })("gpt-5.6-sol"),
  {
    secret: "OPENAI_API_KEY",
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
    scope: (rc) => ({ with: { tenants: String(rc.get("tenant")) } }),
  },
)
```

Also exports `seekritRequestContext` (server middleware that lifts a tenant
header into the request context) and `seekritToolFetch` (a `fetch` narrowed to a
single tool's secrets). Nothing here imports `@mastra/core` — every Mastra shape
is typed structurally, so `@seekrit/sdk` stays dependency-free. Details:
<https://seekrit.dev/docs/guides/frameworks/mastra>.

### Cloudflare Computer

`@seekrit/sdk/cloudflare-computer` turns the Workspace's egress hook into the
proxy: the sandbox holds placeholders, your Worker holds the credentials.

```ts
import { seekritEgress, seekritEgressPolicy, seekritEnv } from "@seekrit/sdk/cloudflare-computer";

export class SeekritGateway extends WorkerEntrypoint<Env> {
  #egress = seekritEgress({
    token: this.env.SEEKRIT_TOKEN,
    allow: { "api.openai.com": ["OPENAI_API_KEY"] },
  });
  override fetch(request: Request) {
    return this.#egress.fetch(request);
  }
}

// on the Durable Object that owns the Workspace
readonly egress = seekritEgressPolicy(this.ctx.exports.SeekritGateway({}), "v1");

// and the command that runs inside it
using run = await ws.runtime.exec(
  'curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models',
  { env: seekritEnv(["OPENAI_API_KEY"]) },
);
```

Cloudflare Computer routes every backend's egress — the container's `curl`, the
worker shell's, and `fetch` in the JavaScript isolate — through one `Fetcher`,
as already-parsed requests. So this is the proxy's boundary without the proxy's
setup: no sidecar, no `HTTPS_PROXY`, no local CA. It is default-deny on the
operation as well as the secret, so it is an egress firewall and not only a
credential shim, and unlike the in-process shim above the workload cannot reach
around it. `resolveEnv()` covers the other case — your own build or migration,
where the command must hold the value.

Rules can also come from a **signed `ap1.` policy bundle** instead of from
source, so a narrowing published from the dashboard reaches a deployed Worker
without a redeploy:

```ts
seekritEgress({
  token: env.SEEKRIT_TOKEN,
  policy: {
    signers: env.POLICY_SIGNERS.split(','),   // the trust anchor, from your config
    agent: 'nova',
    ceiling: { 'api.openai.com': ['OPENAI_API_KEY'] },
    store: {                                   // optional: shared across isolates
      get: (key) => env.POLICY_KV.get(key),
      put: (key, envelope, ttl) => env.POLICY_KV.put(key, envelope, { expirationTtl: ttl }),
    },
    waitUntil: (p) => ctx.waitUntil(p),
  },
});
```

The bundle is signed in the browser, so the API serves bytes it cannot forge and
nothing is enforced until the signature checks out against signers you pinned.
`verifyPolicyBundle` is exported on its own if you want to verify one yourself;
it is pinned to the same golden vectors as the Rust verifier the proxy uses.
Details: <https://seekrit.dev/docs/guides/sandboxes/cloudflare-computer>.
## React and Next.js

`@seekrit/sdk/react` reads secrets in a **server component**, once per render:

```tsx
import { secret } from "@seekrit/sdk/react";

export default async function Page() {
  const key = await secret("STRIPE_KEY");
  const charges = await listCharges(key);
  return <Charges rows={charges} />;   // the key does not cross the boundary
}
```

The resolve is wrapped in React's `cache`, so a page whose components each ask
for a secret still makes one `/v1/resolve` call. Every value is also passed to
React's taint API, so passing one to a client component throws *during render*
instead of serializing it into the RSC payload — enable it with
`experimental: { taint: true }` in `next.config`, and ask for `taint: "require"`
to make a missing taint API an error rather than a warning.

There is no client hook, because a `skt_` service token in a client bundle is a
published credential. For a call the browser has to make itself, keep the
placeholder on the client and substitute it in a route handler:

```ts
// app/api/openai/[...path]/route.ts
import { seekritRoute } from "@seekrit/sdk/route";
import { auth } from "@/auth";

export const { GET, POST } = seekritRoute({
  upstream: "https://api.openai.com",
  allow: { "api.openai.com": ["OPENAI_API_KEY"] },
  authorize: async (request) => (await auth(request)) !== null,
});
```

```ts
// on the client — no key in the bundle
const openai = createOpenAI({ baseURL: "/api/openai/v1", apiKey: "{{seekrit:OPENAI_API_KEY}}" });
```

`authorize` is required and has no default: this handler is reachable from the
internet under your own cookies, so an unauthenticated one is an open credential
proxy. It also drops `cookie` and any non-placeholder `authorization` on the way
out, strips `set-cookie` on the way back, and — unlike `seekritFetch` — gates
*every* request against the allowlist's `methods` and `paths`, not only the ones
carrying a placeholder. Both entrypoints are server-only and refuse to load in a
client bundle. Details:
<https://seekrit.dev/docs/guides/react>.

## Vite

`@seekrit/sdk/vite` resolves your environment from inside `vite.config.ts`, so
the dev server, the build, and Vitest all get it with no wrapper command:

```ts
import { defineConfig } from "vite";
import { seekritVite } from "@seekrit/sdk/vite";

export default defineConfig({
  plugins: [seekritVite()],
});
```

Values land in `process.env` before Vite reads its own environment, so
`import.meta.env` works for the prefixed names and everything else stays
server-side. Vite's `envPrefix` is the line between the two and the plugin never
crosses it: `expose` can narrow which `VITE_*` names reach the bundle
(`"prefixed"`, `"none"`, or a list), and a non-prefixed name can't be published
at all. Authentication is `$SEEKRIT_TOKEN` if set, otherwise the `seekrit` CLI's
login session. Details, framework notes, and the options table:
<https://seekrit.dev/docs/guides/vite>.

This entry point runs in the Vite process (Node, Bun, or Deno) — it is the one
part of the package that is not browser- or Worker-safe.

## Secret references

A secret's value may reference another with `${OTHER_SECRET}`. References are
stored literally and expanded here, after the layers are merged — so a reference
picks up whichever layer won that name, and rotating the referenced secret
updates every value that uses it. `$${OTHER_SECRET}` is a literal; an unknown
name is left as written; a reference cycle raises. Full rules:
[seekrit.dev/docs/guides/references](https://seekrit.dev/docs/guides/references).

```ts
const client = new Seekrit({ interpolate: false }); // get the stored text instead
```

## Zero-knowledge

`GET /v1/resolve` returns ciphertext plus a data-encryption key wrapped to your
token's public key. This SDK recovers the token's private key, unwraps the DEK
(ECDH P-256 → HKDF-SHA256 → AES-256-GCM), and decrypts each secret
(AES-256-GCM, AAD-bound to `environmentId/NAME`) — the exact scheme used by the
CLI, `seekrit run`, and every other seekrit client. See
[seekrit.dev/docs](https://seekrit.dev/docs/concepts/encryption).

## License

MIT

## Vault — your users' credentials for your agent

`@seekrit/sdk/vault` is the platform side of [seekrit Vault](https://seekrit.dev/docs/guides/vault):
open a connect link for an end user, poll it, and make provider requests *as
that user* through the executor in your own Cloudflare account. No credential
ever exists in this process.

```ts
import { Vault } from "@seekrit/sdk/vault";

const vault = new Vault(); // SEEKRIT_VAULT_KEY, VAULT_EXECUTOR_URL, VAULT_EXECUTOR_TOKEN

const link = await vault.connect.create({ userRef: "u_123", providerId: "resend" });
// text link.url to the user …

const res = await vault.fetch({
  userRef: "u_123",
  connectionId,
  request: { method: "POST", url: "https://api.resend.com/emails", body },
});
```

The link's `x` and `k` (executor origin and key thumbprint) come from *your*
executor, never from the API — see the [trust model](https://seekrit.dev/docs/concepts/vault).

The same calls cover an OAuth provider (`providerId: "google-gmail"`): the
person signs in with the provider from the Connect page, the executor keeps the
tokens and refreshes them, and `vault.fetch` injects the access token — or
substitutes `{{seekrit:ACCESS_TOKEN}}` where your request carries it.

Sites with no API are browser sessions: `vault.browser.open()` hands you a
signed-in Browser Run session for your own tools, `fill()` types a saved login
field into the focused input (login origins only), `release()` saves the
rotated session back. `vault.manage.create()` gives the person a page to see
and disconnect what you hold for them; `vault.webhooks.create()` plus
`verifyWebhook()` tell your backend when a connection becomes ready, needs
re-authentication, or is revoked.
