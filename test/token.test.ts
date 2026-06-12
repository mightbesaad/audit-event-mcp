import { describe, expect, it } from "vitest";
import { mintApprovalToken, verifyApprovalToken } from "@/lib/token";

const SECRET = "test-secret-0123456789abcdef";
const PAYLOAD = {
  clientId: "client-test",
  approvalId: "AbCdEfGhIjKlMnOpQrStUv",
  exp: Math.floor(Date.now() / 1000) + 3600,
};

describe("approval link token", () => {
  it("round-trips mint → verify", async () => {
    const token = await mintApprovalToken(SECRET, PAYLOAD);
    expect(token).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const verified = await verifyApprovalToken(SECRET, token);
    expect(verified).toEqual(PAYLOAD);
  });

  it("rejects a tampered signature", async () => {
    const token = await mintApprovalToken(SECRET, PAYLOAD);
    // Tamper the FIRST signature char: the 32-byte sig is 43 base64url chars, so the last
    // char carries only 4 significant bits — flipping it can decode to the identical
    // signature (flaked ~1 in 64 runs). Every bit of the first char is significant.
    const [v, p, sig] = token.split(".") as [string, string, string];
    const flipped = `${v}.${p}.${(sig[0] === "A" ? "B" : "A") + sig.slice(1)}`;
    expect(await verifyApprovalToken(SECRET, flipped)).toBeNull();
  });

  it("rejects a tampered payload (tenant swap)", async () => {
    const token = await mintApprovalToken(SECRET, PAYLOAD);
    const [v, , sig] = token.split(".") as [string, string, string];
    const forged = btoa(
      JSON.stringify({ c: "victim-tenant", a: PAYLOAD.approvalId, e: PAYLOAD.exp }),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    expect(await verifyApprovalToken(SECRET, `${v}.${forged}.${sig}`)).toBeNull();
  });

  it("rejects the wrong secret", async () => {
    const token = await mintApprovalToken(SECRET, PAYLOAD);
    expect(await verifyApprovalToken("other-secret", token)).toBeNull();
  });

  it("rejects an expired token", async () => {
    const past = Math.floor(Date.now() / 1000) - 10;
    const token = await mintApprovalToken(SECRET, { ...PAYLOAD, exp: past });
    expect(await verifyApprovalToken(SECRET, token)).toBeNull();
  });

  it("accepts a token expiring in the future relative to an explicit now", async () => {
    const token = await mintApprovalToken(SECRET, PAYLOAD);
    const beforeExp = (PAYLOAD.exp - 60) * 1000;
    expect(await verifyApprovalToken(SECRET, token, beforeExp)).toEqual(PAYLOAD);
    const afterExp = (PAYLOAD.exp + 60) * 1000;
    expect(await verifyApprovalToken(SECRET, token, afterExp)).toBeNull();
  });

  it("rejects garbage without throwing", async () => {
    for (const garbage of [
      "",
      "v1",
      "v1..",
      "not-a-token",
      "v2.abc.def",
      `v1.${"x".repeat(2000)}.sig`,
      "v1.!!!.###",
      "v1.bm90LWpzb24.AAAA", // valid b64 of "not-json", bogus sig
    ]) {
      expect(await verifyApprovalToken(SECRET, garbage)).toBeNull();
    }
  });

  it("rejects payloads with malformed ids even when correctly signed", async () => {
    // Sign a payload whose clientId would be dangerous as a DO-name component.
    const evil = JSON.stringify({ c: "../escape", a: PAYLOAD.approvalId, e: PAYLOAD.exp });
    const payloadB64 = btoa(evil).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const signedPart = `v1.${payloadB64}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPart));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    expect(await verifyApprovalToken(SECRET, `${signedPart}.${sigB64}`)).toBeNull();
  });

  it("mint refuses invalid inputs", async () => {
    await expect(mintApprovalToken("", PAYLOAD)).rejects.toThrow();
    await expect(mintApprovalToken(SECRET, { ...PAYLOAD, clientId: "bad/id" })).rejects.toThrow();
    await expect(
      mintApprovalToken(SECRET, { ...PAYLOAD, approvalId: "spaces here" }),
    ).rejects.toThrow();
    await expect(mintApprovalToken(SECRET, { ...PAYLOAD, exp: 1.5 })).rejects.toThrow();
  });

  it("verify with empty secret fails closed", async () => {
    const token = await mintApprovalToken(SECRET, PAYLOAD);
    expect(await verifyApprovalToken("", token)).toBeNull();
  });
});
