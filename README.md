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
