#!/usr/bin/env tsx
/// <reference types="node" />
// Onboard a new client: applies CF Resource Tags on the audit-event-mcp Worker script.
// Tags record the client for cost attribution and inventory (Decision #18).
//
// Requires: CF_API_TOKEN env var with Workers Scripts:Edit permission
//
// Usage:
//   CF_API_TOKEN=<token> npx tsx src/scripts/onboard-client.ts \
//     --client-id acme-crm --tier free --region eu

export {}; // make this a module so top-level await is allowed

const CF_API = "https://api.cloudflare.com/client/v4";
const WORKER_NAME = "audit-event-mcp";

interface CfResponse<T> {
  success: boolean;
  result: T;
  errors?: Array<{ code: number; message: string }>;
}

function parseArgs(): { clientId: string; tier: string; region: string } {
  const args = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };
  const clientId = get("--client-id");
  const tier = get("--tier");
  const region = get("--region");

  if (!clientId || !tier || !region) {
    console.error("Usage: onboard-client.ts --client-id <id> --tier <free|paid> --region <region>");
    process.exit(1);
  }
  if (!/^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/.test(clientId)) {
    console.error("client-id must be lowercase alphanumeric with hyphens, 2–63 chars");
    process.exit(1);
  }
  if (!["free", "paid"].includes(tier)) {
    console.error("tier must be 'free' or 'paid'");
    process.exit(1);
  }
  return { clientId, tier, region };
}

async function cfFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = process.env.CF_API_TOKEN;
  if (!token) {
    console.error("Error: CF_API_TOKEN env var is required");
    process.exit(1);
  }
  const res = await fetch(`${CF_API}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(init.headers as Record<string, string> | undefined),
    },
  });
  const body = (await res.json()) as CfResponse<T>;
  if (!body.success) {
    const msg = body.errors?.map((e) => `${e.code}: ${e.message}`).join(", ") ?? "unknown error";
    throw new Error(`CF API ${path} failed — ${msg}`);
  }
  return body.result;
}

async function getAccountId(): Promise<string> {
  const accounts = await cfFetch<Array<{ id: string; name: string }>>("/accounts?per_page=1");
  const first = accounts[0];
  if (!first) throw new Error("No CF accounts found for this token");
  return first.id;
}

async function getCurrentTags(accountId: string): Promise<string[]> {
  try {
    return await cfFetch<string[]>(`/accounts/${accountId}/workers/scripts/${WORKER_NAME}/tags`);
  } catch {
    // Worker not yet deployed or no tags — treat as empty
    return [];
  }
}

async function putTags(accountId: string, tags: string[]): Promise<void> {
  await cfFetch<string[]>(`/accounts/${accountId}/workers/scripts/${WORKER_NAME}/tags`, {
    method: "PUT",
    body: JSON.stringify(tags),
  });
}

// --- main ---

const { clientId, tier, region } = parseArgs();

console.log(`[onboard-client] client-id=${clientId} tier=${tier} region=${region}`);

const accountId = await getAccountId();
console.log(`[onboard-client] account=${accountId}`);

const existing = await getCurrentTags(accountId);

// Per-client tags: client:{id}, tier:{id}:{tier}, region:{id}:{region}
// Existing tier/region tags for this client are replaced; other clients' tags are preserved.
const clientTag = `client:${clientId}`;
const tierTag = `tier:${clientId}:${tier}`;
const regionTag = `region:${clientId}:${region}`;

const filtered = existing.filter(
  (t) => !t.startsWith(`tier:${clientId}:`) && !t.startsWith(`region:${clientId}:`),
);
const merged = [...new Set([...filtered, clientTag, tierTag, regionTag])];

await putTags(accountId, merged);

console.log(`[onboard-client] Tags applied to ${WORKER_NAME}:`);
for (const t of merged) {
  console.log(`  ${t}`);
}

console.log(`
[onboard-client] Next steps (manual, CF Access dashboard):
  1. Open CF Access → Applications → audit-event.kajaril.com
  2. Create a Service Token for this client
  3. In the application's JWT configuration, add a custom claim:
       custom.client_id = "${clientId}"
  4. Share the service token client_id and client_secret with the client
  5. Verify connectivity:
       curl https://audit-event.kajaril.com/health \\
            -H 'CF-Access-Client-Id: <client_id>' \\
            -H 'CF-Access-Client-Secret: <client_secret>'
`);
