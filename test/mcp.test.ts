import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { verifyJwt } from "../src/index";

// --- helpers ---

function toBase64Url(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// --- shared key material ---

let privateKey: CryptoKey;
let publicJwk: JsonWebKey;
const KID = "test-key-1";
const TEAM_DOMAIN = "testteam.cloudflareaccess.com";
const APP_AUD = "a".repeat(64);

async function makeJwt(
  opts: {
    kid?: string;
    exp?: number;
    custom?: Record<string, unknown>;
    aud?: string | string[];
  } = {},
): Promise<string> {
  const header = toBase64Url(JSON.stringify({ alg: "ES256", kid: opts.kid ?? KID, typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = toBase64Url(
    JSON.stringify({
      iss: `https://${TEAM_DOMAIN}`,
      sub: "service-token",
      iat: now,
      exp: opts.exp ?? now + 3600,
      ...("aud" in opts ? { aud: opts.aud } : { aud: [APP_AUD] }),
      ...("custom" in opts ? { custom: opts.custom } : { custom: { client_id: "test-client" } }),
    }),
  );
  const dataToSign = new TextEncoder().encode(`${header}.${payload}`);
  const sigBytes = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    dataToSign,
  );
  return `${header}.${payload}.${toBase64Url(new Uint8Array(sigBytes))}`;
}

beforeAll(async () => {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  privateKey = kp.privateKey;
  publicJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
});

// --- ES256 happy-path and failure cases ---

describe("verifyJwt — ES256", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/cdn-cgi/access/certs")) {
        return new Response(JSON.stringify({ keys: [{ ...publicJwk, kid: KID, use: "sig" }] }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns clientId for a valid ES256 JWT", async () => {
    expect(await verifyJwt(await makeJwt(), TEAM_DOMAIN, APP_AUD)).toBe("test-client");
  });

  it("returns null for a tampered signature", async () => {
    const jwt = await makeJwt();
    const [h, p] = jwt.split(".");
    expect(await verifyJwt(`${h}.${p}.deadbeef`, TEAM_DOMAIN, APP_AUD)).toBeNull();
  });

  it("returns null for an expired JWT", async () => {
    const jwt = await makeJwt({ exp: Math.floor(Date.now() / 1000) - 1 });
    expect(await verifyJwt(jwt, TEAM_DOMAIN, APP_AUD)).toBeNull();
  });

  it("returns null when kid is absent from JWKS", async () => {
    const jwt = await makeJwt({ kid: "unknown-key" });
    expect(await verifyJwt(jwt, TEAM_DOMAIN, APP_AUD)).toBeNull();
  });

  it("returns null when custom.client_id is missing", async () => {
    const jwt = await makeJwt({ custom: {} });
    expect(await verifyJwt(jwt, TEAM_DOMAIN, APP_AUD)).toBeNull();
  });

  it("returns null when custom claim is absent entirely", async () => {
    const jwt = await makeJwt({ custom: undefined });
    expect(await verifyJwt(jwt, TEAM_DOMAIN, APP_AUD)).toBeNull();
  });

  it("returns null for a malformed JWT (not 3 parts)", async () => {
    expect(await verifyJwt("only.two", TEAM_DOMAIN, APP_AUD)).toBeNull();
    expect(await verifyJwt("a.b.c.d.e", TEAM_DOMAIN, APP_AUD)).toBeNull();
  });

  // The aud pin (Day 4): a token for a DIFFERENT Access app on the same team domain is
  // signed by the same keys and would otherwise verify here.
  it("returns null when aud names another Access application", async () => {
    const jwt = await makeJwt({ aud: ["f".repeat(64)] });
    expect(await verifyJwt(jwt, TEAM_DOMAIN, APP_AUD)).toBeNull();
  });

  it("returns null when the aud claim is absent", async () => {
    const jwt = await makeJwt({ aud: undefined });
    expect(await verifyJwt(jwt, TEAM_DOMAIN, APP_AUD)).toBeNull();
  });

  it("accepts a bare-string aud that matches the pin", async () => {
    const jwt = await makeJwt({ aud: APP_AUD });
    expect(await verifyJwt(jwt, TEAM_DOMAIN, APP_AUD)).toBe("test-client");
  });

  it("returns null when the expected aud is empty (never an accept-all pin)", async () => {
    expect(await verifyJwt(await makeJwt(), TEAM_DOMAIN, "")).toBeNull();
  });
});

describe("verifyJwt — JWKS fetch errors", () => {
  it("returns null when the JWKS endpoint is unreachable", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("Network error");
    });
    // Use a domain not in cache from the previous describe block
    const result = await verifyJwt(await makeJwt(), "unreachable.cloudflareaccess.com", APP_AUD);
    expect(result).toBeNull();
    vi.unstubAllGlobals();
  });

  it("returns null when the JWKS endpoint returns a non-200 status", async () => {
    vi.stubGlobal("fetch", async () => new Response("Not Found", { status: 404 }));
    const result = await verifyJwt(await makeJwt(), "broken.cloudflareaccess.com", APP_AUD);
    expect(result).toBeNull();
    vi.unstubAllGlobals();
  });
});

describe("POST /mcp — reserved approval.* event types (D7)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/cdn-cgi/access/certs")) {
        return new Response(JSON.stringify({ keys: [{ ...publicJwk, kid: KID, use: "sig" }] }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("record_event refuses approval.* types before the DO is ever touched", async () => {
    const idFromName = vi.fn();
    const env = {
      CF_ACCESS_TEAM_DOMAIN: TEAM_DOMAIN,
      CF_ACCESS_APP_AUD: APP_AUD,
      AUDIT_DO: { idFromName, get: vi.fn(), jurisdiction: () => ({ idFromName, get: vi.fn() }) },
    } as never;
    const req = new Request("https://audit-event.kajaril.com/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Access-Jwt-Assertion": await makeJwt(),
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: {
          name: "record_event",
          arguments: {
            eventType: "approval.decided",
            purpose: "fabricated decision",
            sessionId: "s",
            input: { decision: "approved" },
          },
        },
      }),
    });
    const res = await worker.fetch(req, env, {} as never);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32602);
    expect(body.error.message).toContain("reserved");
    expect(idFromName).not.toHaveBeenCalled();
  });
});

describe("POST /mcp — fail-closed auth", () => {
  function mcpRequest(headers: Record<string, string>): Request {
    return new Request("https://audit-event.kajaril.com/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
    });
  }

  it("returns 401 when no CF Access token is present", async () => {
    const res = await worker.fetch(mcpRequest({}), {} as never, {} as never);
    expect(res.status).toBe(401);
  });

  it("returns 503 (refuses to trust an unverified token) when CF_ACCESS_TEAM_DOMAIN is unset", async () => {
    // A forged token with an attacker-chosen client_id must NOT be honored just because the team
    // domain is missing — the old code decoded it unverified and could impersonate any tenant.
    const forged = await makeJwt({ custom: { client_id: "victim-tenant" } });
    const res = await worker.fetch(
      mcpRequest({ "CF-Access-Jwt-Assertion": forged }),
      {} as never,
      {} as never,
    );
    expect(res.status).toBe(503);
  });

  it("returns 503 when CF_ACCESS_APP_AUD is unset — an unpinned aud is a misconfiguration", async () => {
    const res = await worker.fetch(
      mcpRequest({ "CF-Access-Jwt-Assertion": await makeJwt() }),
      { CF_ACCESS_TEAM_DOMAIN: TEAM_DOMAIN } as never,
      {} as never,
    );
    expect(res.status).toBe(503);
  });
});
