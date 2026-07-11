import { describe, expect, it } from "vitest";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  constantTimeEqualHex,
  generateClientSecret,
  mintAccessToken,
  sha256Hex,
  verifyAccessToken,
} from "@/lib/m2m";

const SECRET = "test-signing-secret-with-plenty-of-entropy";
const CLAIMS = { clientId: "client-test", scope: "agent" as const };

function toBase64Url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

describe("generateClientSecret", () => {
  it("prefixes the scope and carries 32 bytes of entropy", () => {
    const agent = generateClientSecret("agent");
    const admin = generateClientSecret("admin");
    expect(agent).toMatch(/^kjr_agent_[A-Za-z0-9_-]{43}$/);
    expect(admin).toMatch(/^kjr_admin_[A-Za-z0-9_-]{43}$/);
  });

  it("never repeats", () => {
    expect(generateClientSecret("agent")).not.toBe(generateClientSecret("agent"));
  });
});

describe("sha256Hex / constantTimeEqualHex", () => {
  it("hashes to 64 hex chars and compares equal hashes equal", async () => {
    const h = await sha256Hex("kjr_agent_x");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(constantTimeEqualHex(h, h)).toBe(true);
  });

  it("detects differing and differing-length inputs", async () => {
    const a = await sha256Hex("a");
    const b = await sha256Hex("b");
    expect(constantTimeEqualHex(a, b)).toBe(false);
    expect(constantTimeEqualHex(a, a.slice(1))).toBe(false);
  });
});

describe("access token round-trip", () => {
  it("mints a token that verifies back to its claims", async () => {
    const token = await mintAccessToken(SECRET, CLAIMS);
    expect(await verifyAccessToken(SECRET, token)).toEqual(CLAIMS);
  });

  it("admin scope survives the round-trip", async () => {
    const token = await mintAccessToken(SECRET, { clientId: "c", scope: "admin" });
    expect(await verifyAccessToken(SECRET, token)).toEqual({ clientId: "c", scope: "admin" });
  });

  it("expires exactly after the TTL", async () => {
    const now = Date.now();
    const token = await mintAccessToken(SECRET, CLAIMS, now);
    const justBefore = now + (ACCESS_TOKEN_TTL_SECONDS - 1) * 1000;
    const justAfter = now + (ACCESS_TOKEN_TTL_SECONDS + 1) * 1000;
    expect(await verifyAccessToken(SECRET, token, justBefore)).toEqual(CLAIMS);
    expect(await verifyAccessToken(SECRET, token, justAfter)).toBeNull();
  });

  it("refuses minting with an empty secret or malformed claims", async () => {
    await expect(mintAccessToken("", CLAIMS)).rejects.toThrow("secret");
    await expect(mintAccessToken(SECRET, { clientId: "../up", scope: "agent" })).rejects.toThrow(
      "clientId",
    );
    await expect(
      mintAccessToken(SECRET, { clientId: "c", scope: "root" as never }),
    ).rejects.toThrow("scope");
  });
});

describe("verifyAccessToken — negative cases", () => {
  it("rejects a token signed with a different secret", async () => {
    const token = await mintAccessToken("other-secret", CLAIMS);
    expect(await verifyAccessToken(SECRET, token)).toBeNull();
  });

  it("rejects a tampered payload (signature no longer matches)", async () => {
    const token = await mintAccessToken(SECRET, CLAIMS);
    const [h, , s] = token.split(".") as [string, string, string];
    const forged = toBase64Url(
      JSON.stringify({
        iss: "audit-event-mcp",
        sub: "victim-tenant",
        scope: "admin",
        iat: 0,
        exp: 4102444800,
      }),
    );
    expect(await verifyAccessToken(SECRET, `${h}.${forged}.${s}`)).toBeNull();
  });

  it('rejects alg confusion: "none" and any non-HS256 alg', async () => {
    const token = await mintAccessToken(SECRET, CLAIMS);
    const [, p, s] = token.split(".") as [string, string, string];
    const noneHeader = toBase64Url(JSON.stringify({ alg: "none", typ: "JWT" }));
    const rsHeader = toBase64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
    expect(await verifyAccessToken(SECRET, `${noneHeader}.${p}.${s}`)).toBeNull();
    expect(await verifyAccessToken(SECRET, `${noneHeader}.${p}.`)).toBeNull();
    expect(await verifyAccessToken(SECRET, `${rsHeader}.${p}.${s}`)).toBeNull();
  });

  it("rejects structurally broken tokens without throwing", async () => {
    for (const garbage of ["", "a", "a.b", "a.b.c.d", "!!.!!.!!", "a.b.c"]) {
      expect(await verifyAccessToken(SECRET, garbage)).toBeNull();
    }
  });

  it("rejects an oversized token before any crypto work", async () => {
    expect(await verifyAccessToken(SECRET, "a".repeat(5000))).toBeNull();
  });

  it("rejects wrong issuer, bad sub shape, unknown scope, and missing exp — even correctly signed", async () => {
    async function signed(payload: Record<string, unknown>): Promise<string> {
      const header = toBase64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const body = toBase64Url(JSON.stringify(payload));
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(SECRET),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
      const sig = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(`${header}.${body}`),
      );
      const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
      return `${header}.${body}.${sigB64}`;
    }

    const future = Math.floor(Date.now() / 1000) + 3600;
    const base = { iss: "audit-event-mcp", sub: "c", scope: "agent", exp: future };

    expect(await verifyAccessToken(SECRET, await signed({ ...base, iss: "evil" }))).toBeNull();
    expect(await verifyAccessToken(SECRET, await signed({ ...base, sub: "../up" }))).toBeNull();
    expect(await verifyAccessToken(SECRET, await signed({ ...base, scope: "root" }))).toBeNull();
    expect(await verifyAccessToken(SECRET, await signed({ ...base, exp: undefined }))).toBeNull();
    expect(await verifyAccessToken(SECRET, await signed({ ...base, exp: "soon" }))).toBeNull();
    expect(await verifyAccessToken(SECRET, await signed(base))).toEqual({
      clientId: "c",
      scope: "agent",
    });
  });

  it("rejects with an empty signing secret", async () => {
    const token = await mintAccessToken(SECRET, CLAIMS);
    expect(await verifyAccessToken("", token)).toBeNull();
  });
});
