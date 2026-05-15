import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyJwt } from "../src/index";

// --- helpers ---

function toBase64Url(input: string | Uint8Array): string {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// --- shared key material ---

let privateKey: CryptoKey;
let publicJwk: JsonWebKey;
const KID = "test-key-1";
const TEAM_DOMAIN = "testteam.cloudflareaccess.com";

async function makeJwt(opts: {
  kid?: string;
  exp?: number;
  custom?: Record<string, unknown>;
} = {}): Promise<string> {
  const header = toBase64Url(
    JSON.stringify({ alg: "ES256", kid: opts.kid ?? KID, typ: "JWT" }),
  );
  const now = Math.floor(Date.now() / 1000);
  const payload = toBase64Url(
    JSON.stringify({
      iss: `https://${TEAM_DOMAIN}`,
      sub: "service-token",
      iat: now,
      exp: opts.exp ?? now + 3600,
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
  const kp = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  privateKey = kp.privateKey;
  publicJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
});

// --- ES256 happy-path and failure cases ---

describe("verifyJwt — ES256", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/cdn-cgi/access/certs")) {
        return new Response(
          JSON.stringify({ keys: [{ ...publicJwk, kid: KID, use: "sig" }] }),
          { headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error(`Unexpected fetch: ${url}`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns clientId for a valid ES256 JWT", async () => {
    expect(await verifyJwt(await makeJwt(), TEAM_DOMAIN)).toBe("test-client");
  });

  it("returns null for a tampered signature", async () => {
    const jwt = await makeJwt();
    const [h, p] = jwt.split(".");
    expect(await verifyJwt(`${h}.${p}.deadbeef`, TEAM_DOMAIN)).toBeNull();
  });

  it("returns null for an expired JWT", async () => {
    const jwt = await makeJwt({ exp: Math.floor(Date.now() / 1000) - 1 });
    expect(await verifyJwt(jwt, TEAM_DOMAIN)).toBeNull();
  });

  it("returns null when kid is absent from JWKS", async () => {
    const jwt = await makeJwt({ kid: "unknown-key" });
    expect(await verifyJwt(jwt, TEAM_DOMAIN)).toBeNull();
  });

  it("returns null when custom.client_id is missing", async () => {
    const jwt = await makeJwt({ custom: {} });
    expect(await verifyJwt(jwt, TEAM_DOMAIN)).toBeNull();
  });

  it("returns null when custom claim is absent entirely", async () => {
    const jwt = await makeJwt({ custom: undefined });
    expect(await verifyJwt(jwt, TEAM_DOMAIN)).toBeNull();
  });

  it("returns null for a malformed JWT (not 3 parts)", async () => {
    expect(await verifyJwt("only.two", TEAM_DOMAIN)).toBeNull();
    expect(await verifyJwt("a.b.c.d.e", TEAM_DOMAIN)).toBeNull();
  });
});

describe("verifyJwt — JWKS fetch errors", () => {
  it("returns null when the JWKS endpoint is unreachable", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("Network error");
    });
    // Use a domain not in cache from the previous describe block
    const result = await verifyJwt(await makeJwt(), "unreachable.cloudflareaccess.com");
    expect(result).toBeNull();
    vi.unstubAllGlobals();
  });

  it("returns null when the JWKS endpoint returns a non-200 status", async () => {
    vi.stubGlobal("fetch", async () => new Response("Not Found", { status: 404 }));
    const result = await verifyJwt(await makeJwt(), "broken.cloudflareaccess.com");
    expect(result).toBeNull();
    vi.unstubAllGlobals();
  });
});
