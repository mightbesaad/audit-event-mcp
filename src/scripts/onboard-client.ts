#!/usr/bin/env tsx
/// <reference types="node" />
// Onboard a new client: apply CF Resource Tags to their DO via CF API.
// DO tagging must be imperative — wrangler.jsonc has no declarative syntax for it.
//
// Usage:
//   npx tsx src/scripts/onboard-client.ts --client-id acme-crm --tier free --region eu-west

// TODO(M8-next): implement CF Resource Tagging via CF API
//   1. POST https://api.cloudflare.com/client/v4/accounts/{account_id}/tags
//   2. Tag the DO namespace binding with client_id, tier, region
//   Requires: CF_API_TOKEN env var with Tags:Edit permission

const args = process.argv.slice(2);
const clientId = args[args.indexOf("--client-id") + 1];
const tier = args[args.indexOf("--tier") + 1];
const region = args[args.indexOf("--region") + 1];

if (!clientId || !tier || !region) {
  console.error("Usage: onboard-client.ts --client-id <id> --tier <free|paid> --region <region>");
  process.exit(1);
}

console.log(`[onboard-client] client-id=${clientId} tier=${tier} region=${region}`);
console.log("[onboard-client] CF Resource Tagging not yet implemented — see TODO above");
process.exit(0);
