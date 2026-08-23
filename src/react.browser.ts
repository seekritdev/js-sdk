/**
 * The `"browser"` condition for `@seekrit/sdk/react`.
 *
 * A bundler building a client bundle resolves to this file, which throws on
 * import — the real module holds a `skt_` service token, and a service token in
 * a client bundle is a published credential. Unconditional on purpose: reaching
 * this file at all means a bundler already decided this code is going to the
 * browser, so there is nothing left to detect. `server-only.ts` holds the
 * runtime half of the guard, for bundlers that ignore export conditions.
 */
import { serverOnlyError } from "./server-only.js";

throw serverOnlyError("react");
