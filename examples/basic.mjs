// Resolve and print secret names (not values) for the token in $SEEKRIT_TOKEN.
//
//   export SEEKRIT_TOKEN=skt_...
//   npm run build && node examples/basic.mjs
import { Seekrit } from "../dist/index.js";

const client = new Seekrit();
const secrets = await client.resolve();
console.log(`resolved ${Object.keys(secrets).length} secret(s):`);
for (const name of Object.keys(secrets).sort()) {
  console.log(`  - ${name}`);
}
