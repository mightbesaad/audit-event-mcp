import { describe, expect, it } from "vitest";
import { computeChainHash, computeInputHash } from "../src/lib/hash";

describe("computeInputHash", () => {
  it("returns 64-char lowercase hex string", async () => {
    const hash = await computeInputHash({ query: "hello" });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", async () => {
    const input = { x: 1, y: "test" };
    expect(await computeInputHash(input)).toBe(await computeInputHash(input));
  });

  it("varies by input value", async () => {
    expect(await computeInputHash("hello")).not.toBe(await computeInputHash("world"));
  });

  it("varies by input structure", async () => {
    expect(await computeInputHash({ a: 1 })).not.toBe(await computeInputHash({ b: 1 }));
  });

  it("handles null and undefined differently from each other", async () => {
    expect(await computeInputHash(null)).not.toBe(await computeInputHash(undefined));
  });
});

describe("computeChainHash", () => {
  it("returns 64-char lowercase hex string", async () => {
    const hash = await computeChainHash({
      id: "01hyz000000000000000000000",
      eventType: "tool.call",
      inputHashSlot: "abc123def456",
      prevHash: null,
    });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", async () => {
    const params = { id: "test-id", eventType: "tool.call", inputHashSlot: "slot", prevHash: null };
    expect(await computeChainHash(params)).toBe(await computeChainHash(params));
  });

  it("null prevHash and empty string prevHash produce the same result (first-record semantics)", async () => {
    const base = { id: "id0", eventType: "tool.call", inputHashSlot: "slot" };
    const withNull = await computeChainHash({ ...base, prevHash: null });
    const withEmpty = await computeChainHash({ ...base, prevHash: "" });
    expect(withNull).toBe(withEmpty);
  });

  it("different inputHashSlot values produce different hashes (omission-reason tamper-evidence)", async () => {
    const base = { id: "id0", eventType: "tool.call", prevHash: null };
    const h1 = await computeChainHash({ ...base, inputHashSlot: "no_personal_data" });
    const h2 = await computeChainHash({ ...base, inputHashSlot: "caller_opted_out" });
    expect(h1).not.toBe(h2);
  });

  it("different prevHash values produce different hashes", async () => {
    const base = { id: "id0", eventType: "tool.call", inputHashSlot: "slot" };
    const h1 = await computeChainHash({ ...base, prevHash: "prev-a" });
    const h2 = await computeChainHash({ ...base, prevHash: "prev-b" });
    expect(h1).not.toBe(h2);
  });

  it("different event ids produce different hashes", async () => {
    const base = { eventType: "tool.call", inputHashSlot: "slot", prevHash: null };
    const h1 = await computeChainHash({ ...base, id: "id-alpha" });
    const h2 = await computeChainHash({ ...base, id: "id-beta" });
    expect(h1).not.toBe(h2);
  });

  it("different event types produce different hashes", async () => {
    const base = { id: "id0", inputHashSlot: "slot", prevHash: null };
    const h1 = await computeChainHash({ ...base, eventType: "tool.call" });
    const h2 = await computeChainHash({ ...base, eventType: "decision.made" });
    expect(h1).not.toBe(h2);
  });
});

describe("chain integrity across a sequence of events", () => {
  it("3-event chain: each hash depends on the previous", async () => {
    const slot0 = await computeInputHash({ step: 0 });
    const chain0 = await computeChainHash({ id: "id0", eventType: "tool.call", inputHashSlot: slot0, prevHash: null });

    const slot1 = await computeInputHash({ step: 1 });
    const chain1 = await computeChainHash({ id: "id1", eventType: "tool.result", inputHashSlot: slot1, prevHash: chain0 });

    const slot2 = await computeInputHash({ step: 2 });
    const chain2 = await computeChainHash({ id: "id2", eventType: "decision.made", inputHashSlot: slot2, prevHash: chain1 });

    expect(new Set([chain0, chain1, chain2]).size).toBe(3);
  });

  it("tampering event 0 cascades through the chain", async () => {
    const slot0 = await computeInputHash({ step: 0 });
    const chain0 = await computeChainHash({ id: "id0", eventType: "tool.call", inputHashSlot: slot0, prevHash: null });

    const slot1 = await computeInputHash({ step: 1 });
    const chain1 = await computeChainHash({ id: "id1", eventType: "tool.result", inputHashSlot: slot1, prevHash: chain0 });

    const tamperedSlot0 = await computeInputHash({ step: "TAMPERED" });
    const tamperedChain0 = await computeChainHash({ id: "id0", eventType: "tool.call", inputHashSlot: tamperedSlot0, prevHash: null });
    const tamperedChain1 = await computeChainHash({ id: "id1", eventType: "tool.result", inputHashSlot: slot1, prevHash: tamperedChain0 });

    expect(tamperedChain0).not.toBe(chain0);
    expect(tamperedChain1).not.toBe(chain1);
  });

  it("mixed-omission chain: omitted-reason slot preserves chain integrity", async () => {
    const inputHash = await computeInputHash({ data: "sensitive" });
    const chain0 = await computeChainHash({ id: "id0", eventType: "human.turn", inputHashSlot: inputHash, prevHash: null });

    // Second event: caller omitted input
    const chain1 = await computeChainHash({ id: "id1", eventType: "tool.call", inputHashSlot: "no_personal_data", prevHash: chain0 });

    // Third event: real input again
    const slot2 = await computeInputHash({ result: "ok" });
    const chain2 = await computeChainHash({ id: "id2", eventType: "tool.result", inputHashSlot: slot2, prevHash: chain1 });

    expect(new Set([chain0, chain1, chain2]).size).toBe(3);
  });
});
