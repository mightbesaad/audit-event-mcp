async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function computeInputHash(input: unknown): Promise<string> {
  return sha256Hex(JSON.stringify(input));
}

export async function computeChainHash(params: {
  id: string;
  eventType: string;
  inputHashSlot: string;
  prevHash: string | null;
}): Promise<string> {
  const { id, eventType, inputHashSlot, prevHash } = params;
  return sha256Hex(`${id}|${eventType}|${inputHashSlot}|${prevHash ?? ""}`);
}
