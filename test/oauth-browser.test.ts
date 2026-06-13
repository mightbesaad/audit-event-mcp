import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "@/index";
import { mintConsentState, verifyConsentState } from "@/lib/oauth-browser";
import type { Env } from "@/lib/types";

// Browser OAuth flow (D11) — the library-owned surfaces tested at the same adversarial
// depth as the hand-rolled paths (founder condition 5): hostile DCR registrants, consent
// injection attempts, CSRF/confused-deputy on the decision POST, PKCE enforcement, and the
// six shim conditions at /oauth/token.

const ORIGIN = "https://audit-event.kajaril.com";
const TEAM_DOMAIN = "day5team.cloudflareaccess.com";
const APP_AUD = "b".repeat(64);
const SIGNING_SECRET = "test-consent-signing-secret";
const TENANT = "tenant-day5";

// --- CF Access JWT scaffolding (pattern from mcp.test.ts) ---

function toBase64Url(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

let privateKey: CryptoKey;
let publicJwk: JsonWebKey;
const KID = "day5-key";

async function makeAccessJwt(clientId: string = TENANT): Promise<string> {
  const header = toBase64Url(JSON.stringify({ alg: "ES256", kid: KID, typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = toBase64Url(
    JSON.stringify({
      iss: `https://${TEAM_DOMAIN}`,
      sub: "operator",
      iat: now,
      exp: now + 3600,
      aud: [APP_AUD],
      custom: { client_id: clientId },
    }),
  );
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${toBase64Url(new Uint8Array(sig))}`;
}

beforeAll(async () => {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  privateKey = kp.privateKey;
  publicJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
});

// --- OAUTH_KV mock: the library needs get-as-json, put, delete, and prefix list ---

function makeOAuthKV(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: async (key: string, opts?: { type?: string } | string) => {
      const value = store.get(key) ?? null;
      if (value === null) return null;
      const type = typeof opts === "string" ? opts : opts?.type;
      return type === "json" ? JSON.parse(value) : value;
    },
    put: async (key: string, value: string, _opts?: unknown) => {
      store.set(key, value);
    },
    delete: async (key: string) => {
      store.delete(key);
    },
    list: async (opts?: { prefix?: string }) => ({
      keys: [...store.keys()]
        .filter((k) => !opts?.prefix || k.startsWith(opts.prefix))
        .map((name) => ({ name })),
      list_complete: true,
    }),
  } as unknown as KVNamespace;
}

// --- helpers ---

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    AUDIT_DO: {
      idFromName: () => {
        throw new Error("no DO expected in this test");
      },
      get: () => {
        throw new Error("no DO expected in this test");
      },
    } as unknown as Env["AUDIT_DO"],
    OAUTH_KV: makeOAuthKV(),
    M2M_TOKEN_SIGNING_SECRET: SIGNING_SECRET,
    CF_ACCESS_TEAM_DOMAIN: TEAM_DOMAIN,
    CF_ACCESS_APP_AUD: APP_AUD,
    ...overrides,
  } as Env;
}

async function dcrRegister(
  env: Env,
  metadata: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return worker.fetch(
    new Request(`${ORIGIN}/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(metadata),
    }),
    env,
    {} as never,
  );
}

async function registerPublicClient(
  env: Env,
  extra: Record<string, unknown> = {},
): Promise<{ client_id: string }> {
  const res = await dcrRegister(env, {
    client_name: "Day-5 Test Client",
    redirect_uris: ["https://client.example/callback"],
    token_endpoint_auth_method: "none",
    ...extra,
  });
  expect(res.status).toBeLessThan(300);
  return (await res.json()) as { client_id: string };
}

async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = toBase64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  return { verifier, challenge };
}

function authorizeUrl(params: Record<string, string>): string {
  return `${ORIGIN}/oauth/authorize?${new URLSearchParams(params)}`;
}

async function getConsent(env: Env, params: Record<string, string>, jwt?: string) {
  return worker.fetch(
    new Request(authorizeUrl(params), {
      headers: jwt ? { "CF-Access-Jwt-Assertion": jwt } : {},
    }),
    env,
    {} as never,
  );
}

function extractConsentState(html: string): string {
  const match = /name="consent_state" value="([^"]+)"/.exec(html);
  expect(match).not.toBeNull();
  return (match as RegExpExecArray)[1] as string;
}

async function postDecision(
  env: Env,
  fields: Record<string, string>,
  jwt?: string,
): Promise<Response> {
  return worker.fetch(
    new Request(`${ORIGIN}/oauth/authorize/decision`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(jwt ? { "CF-Access-Jwt-Assertion": jwt } : {}),
      },
      body: new URLSearchParams(fields),
    }),
    env,
    {} as never,
  );
}

async function tokenPost(
  env: Env,
  body: Record<string, string>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return worker.fetch(
    new Request(`${ORIGIN}/oauth/token`, {
      method: "POST",
      headers,
      body: new URLSearchParams(body),
    }),
    env,
    {} as never,
  );
}

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/cdn-cgi/access/certs")) {
        return Response.json({ keys: [{ ...publicJwk, kid: KID }] });
      }
      throw new Error(`unexpected outbound fetch in test: ${url}`);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// --- DCR: hostile registrants are the norm (D11 condition 5) ---

describe("POST /oauth/register — hostile DCR registrants", () => {
  it("registers a public MCP-style client without a secret", async () => {
    const env = makeEnv();
    const res = await dcrRegister(env, {
      client_name: "Legit MCP Client",
      redirect_uris: ["http://localhost:33418/callback"],
      token_endpoint_auth_method: "none",
    });
    expect(res.status).toBeLessThan(300);
    const body = (await res.json()) as { client_id: string; client_secret?: string };
    expect(body.client_id).toBeTruthy();
    expect(body.client_secret).toBeUndefined();
  });

  it("rejects javascript: and data: metadata URIs (the 0.7.2 consent-sink fix)", async () => {
    const env = makeEnv();
    for (const field of ["logo_uri", "client_uri", "policy_uri", "tos_uri", "jwks_uri"]) {
      for (const uri of ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"]) {
        const res = await dcrRegister(env, {
          redirect_uris: ["https://client.example/cb"],
          [field]: uri,
        });
        expect(res.status, `${field} = ${uri}`).toBe(400);
        expect(((await res.json()) as { error: string }).error).toBe("invalid_client_metadata");
      }
    }
  });

  it("rejects javascript: URIs smuggled through i18n variants (#218 bypass)", async () => {
    const env = makeEnv();
    const res = await dcrRegister(env, {
      redirect_uris: ["https://client.example/cb"],
      "client_uri#en": "javascript:alert(1)",
    });
    expect(res.status).toBe(400);
  });

  it("rejects dangerous redirect_uri schemes and control characters", async () => {
    const env = makeEnv();
    for (const uri of [
      "javascript:alert(1)",
      "data:text/html,x",
      "vbscript:x",
      "file:///etc/passwd",
      "https://client.example/cb ",
      "not-a-uri",
    ]) {
      const res = await dcrRegister(env, { redirect_uris: [uri] });
      expect(res.status, `redirect_uri = ${JSON.stringify(uri)}`).toBe(400);
    }
  });

  it("refuses oversized registration payloads (1 MiB cap)", async () => {
    const env = makeEnv();
    const res = await dcrRegister(
      env,
      { redirect_uris: ["https://client.example/cb"] },
      { "Content-Length": String(2 * 1024 * 1024) },
    );
    expect(res.status).toBe(413);
  });

  it("is per-IP rate capped at the shim, like the token endpoint", async () => {
    const limit = vi.fn(async () => ({ success: false }));
    const env = makeEnv({ APPROVAL_RATE_LIMITER: { limit } as unknown as RateLimit });
    const res = await dcrRegister(
      env,
      { redirect_uris: ["https://client.example/cb"] },
      { "CF-Connecting-IP": "203.0.113.7" },
    );
    expect(res.status).toBe(429);
    expect(limit).toHaveBeenCalledWith({ key: "reg-ip:203.0.113.7" });
  });

  it("fails closed (503) without OAUTH_KV", async () => {
    const env = makeEnv({ OAUTH_KV: undefined });
    const res = await dcrRegister(env, { redirect_uris: ["https://client.example/cb"] });
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("temporarily_unavailable");
  });
});

// --- RFC 8414 / RFC 9728 metadata (D11 condition 4) ---

describe("OAuth metadata", () => {
  it("advertises the single /oauth/token for all three grants", async () => {
    const env = makeEnv();
    const res = await worker.fetch(
      new Request(`${ORIGIN}/.well-known/oauth-authorization-server`),
      env,
      {} as never,
    );
    expect(res.status).toBe(200);
    const meta = (await res.json()) as Record<string, unknown>;
    expect(meta.token_endpoint).toBe(`${ORIGIN}/oauth/token`);
    expect(meta.authorization_endpoint).toBe(`${ORIGIN}/oauth/authorize`);
    expect(meta.registration_endpoint).toBe(`${ORIGIN}/oauth/register`);
    expect(meta.grant_types_supported).toEqual([
      "authorization_code",
      "refresh_token",
      "client_credentials",
    ]);
    expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
    expect(meta.scopes_supported).toEqual(["agent", "admin"]);
  });

  it("serves protected-resource metadata pointing at this origin", async () => {
    const env = makeEnv();
    const res = await worker.fetch(
      new Request(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`),
      env,
      {} as never,
    );
    expect(res.status).toBe(200);
    const meta = (await res.json()) as { resource: string; authorization_servers: string[] };
    expect(meta.resource).toBe(`${ORIGIN}/mcp`);
    expect(meta.authorization_servers).toEqual([ORIGIN]);
  });
});

// --- consent page (GET /oauth/authorize) ---

describe("GET /oauth/authorize — consent", () => {
  async function validParams(env: Env, extra: Record<string, string> = {}) {
    const { client_id } = await registerPublicClient(env);
    const { challenge, verifier } = await pkcePair();
    return {
      verifier,
      clientId: client_id,
      params: {
        response_type: "code",
        client_id,
        redirect_uri: "https://client.example/callback",
        scope: "agent",
        state: "client-state-123",
        code_challenge: challenge,
        code_challenge_method: "S256",
        ...extra,
      },
    };
  }

  it("requires a signed-in operator (CF Access JWT) — Bearer tokens cannot consent", async () => {
    const env = makeEnv();
    const { params } = await validParams(env);
    const res = await getConsent(env, params);
    expect(res.status).toBe(401);
    expect(await res.text()).toContain("Sign-in required");
  });

  it("renders the consent card with tenant, scopes, and CSRF state for a valid request", async () => {
    const env = makeEnv();
    const { params } = await validParams(env);
    const res = await getConsent(env, params, await makeAccessJwt());
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Security-Policy")).toContain("script-src 'none'");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const html = await res.text();
    expect(html).toContain(TENANT);
    expect(html).toContain("agent");
    expect(html).not.toContain("<script");
    extractConsentState(html);
  });

  it("escapes a hostile DCR client_name — markup never reaches the DOM", async () => {
    const env = makeEnv();
    const hostileName = '<script>alert(1)</script><img src=x onerror=alert(2)>"><b>x</b>';
    const { client_id } = await registerPublicClient(env, { client_name: hostileName });
    const { challenge } = await pkcePair();
    const res = await getConsent(
      env,
      {
        response_type: "code",
        client_id,
        redirect_uri: "https://client.example/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
      await makeAccessJwt(),
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).not.toContain("<script>alert(1)");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("refuses an unknown client without redirecting", async () => {
    const env = makeEnv();
    const res = await getConsent(
      env,
      {
        response_type: "code",
        client_id: "no-such-client",
        redirect_uri: "https://attacker.example/cb",
      },
      await makeAccessJwt(),
    );
    expect(res.status).toBe(400);
    expect(res.headers.get("Location")).toBeNull();
  });

  it("refuses a redirect_uri the client never registered — no open redirect", async () => {
    const env = makeEnv();
    const { params } = await validParams(env, { redirect_uri: "https://attacker.example/steal" });
    const res = await getConsent(env, params, await makeAccessJwt());
    expect(res.status).toBe(400);
    expect(res.headers.get("Location")).toBeNull();
  });

  it("requires PKCE for public clients", async () => {
    const env = makeEnv();
    const { params } = await validParams(env);
    delete (params as Record<string, string>).code_challenge;
    delete (params as Record<string, string>).code_challenge_method;
    const res = await getConsent(env, params, await makeAccessJwt());
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("PKCE");
  });

  it("bounds the state parameter before it enters the signed blob", async () => {
    const env = makeEnv();
    const { params } = await validParams(env, { state: "s".repeat(3000) });
    const res = await getConsent(env, params, await makeAccessJwt());
    expect(res.status).toBe(400);
  });

  it("fails closed (503) when OAUTH_KV or the signing secret is missing", async () => {
    for (const overrides of [{ OAUTH_KV: undefined }, { M2M_TOKEN_SIGNING_SECRET: undefined }]) {
      const env = makeEnv(overrides as Partial<Env>);
      const res = await getConsent(
        env,
        { response_type: "code", client_id: "x", redirect_uri: "https://c.example/cb" },
        await makeAccessJwt(),
      );
      expect(res.status).toBe(503);
    }
  });
});

// --- decision POST: CSRF / confused deputy ---

describe("POST /oauth/authorize/decision", () => {
  async function consentBlobFor(env: Env, scope = "agent") {
    const { client_id } = await registerPublicClient(env);
    const { challenge, verifier } = await pkcePair();
    const res = await getConsent(
      env,
      {
        response_type: "code",
        client_id,
        redirect_uri: "https://client.example/callback",
        scope,
        state: "xyz-state",
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
      await makeAccessJwt(),
    );
    expect(res.status).toBe(200);
    return { blob: extractConsentState(await res.text()), clientId: client_id, verifier };
  }

  it("approve completes authorization and redirects with a code", async () => {
    const env = makeEnv();
    const { blob } = await consentBlobFor(env);
    const res = await postDecision(
      env,
      { consent_state: blob, decision: "approve" },
      await makeAccessJwt(),
    );
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") as string);
    expect(location.origin).toBe("https://client.example");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe("xyz-state");
  });

  it("deny redirects with error=access_denied and preserves state", async () => {
    const env = makeEnv();
    const { blob } = await consentBlobFor(env);
    const res = await postDecision(
      env,
      { consent_state: blob, decision: "deny" },
      await makeAccessJwt(),
    );
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") as string);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("xyz-state");
    expect(location.searchParams.get("code")).toBeNull();
  });

  it("rejects a tampered consent blob", async () => {
    const env = makeEnv();
    const { blob } = await consentBlobFor(env);
    const tampered = blob.slice(0, -2) + (blob.endsWith("aa") ? "bb" : "aa");
    const res = await postDecision(
      env,
      { consent_state: tampered, decision: "approve" },
      await makeAccessJwt(),
    );
    expect(res.status).toBe(400);
    expect(res.headers.get("Location")).toBeNull();
  });

  it("rejects a blob minted under a different operator session (confused deputy)", async () => {
    const env = makeEnv();
    const { blob } = await consentBlobFor(env);
    const res = await postDecision(
      env,
      { consent_state: blob, decision: "approve" },
      await makeAccessJwt("other-tenant"),
    );
    expect(res.status).toBe(403);
    expect(res.headers.get("Location")).toBeNull();
  });

  it("rejects an expired blob", async () => {
    const env = makeEnv();
    const { clientId } = await consentBlobFor(env);
    const stale = await mintConsentState(
      SIGNING_SECRET,
      {
        tenant: TENANT,
        authRequest: {
          responseType: "code",
          clientId,
          redirectUri: "https://client.example/callback",
          scope: ["agent"],
          state: "",
        },
      },
      Date.now() - 11 * 60 * 1000,
    );
    expect(await verifyConsentState(SIGNING_SECRET, stale)).toBeNull();
    const res = await postDecision(
      env,
      { consent_state: stale, decision: "approve" },
      await makeAccessJwt(),
    );
    expect(res.status).toBe(400);
  });

  it("rejects unknown decisions and missing fields", async () => {
    const env = makeEnv();
    const { blob } = await consentBlobFor(env);
    const badFields: Record<string, string>[] = [
      { consent_state: blob, decision: "yes-please" },
      { decision: "approve" },
    ];
    for (const fields of badFields) {
      const res = await postDecision(env, fields, await makeAccessJwt());
      expect(res.status).toBe(400);
    }
  });
});

// --- the shim: grant_type routing + the full code exchange (D11 conditions 1–3) ---

describe("POST /oauth/token — shim routing", () => {
  async function approvedCode(env: Env, scope = "agent") {
    const { client_id } = await registerPublicClient(env);
    const { challenge, verifier } = await pkcePair();
    const consentRes = await getConsent(
      env,
      {
        response_type: "code",
        client_id,
        redirect_uri: "https://client.example/callback",
        scope,
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
      await makeAccessJwt(),
    );
    const blob = extractConsentState(await consentRes.text());
    const decideRes = await postDecision(
      env,
      { consent_state: blob, decision: "approve" },
      await makeAccessJwt(),
    );
    const location = new URL(decideRes.headers.get("Location") as string);
    return {
      clientId: client_id,
      verifier,
      code: location.searchParams.get("code") as string,
    };
  }

  it("exchanges an authorization code (PKCE) and the token works on /mcp", async () => {
    const env = makeEnv();
    const { clientId, verifier, code } = await approvedCode(env);
    const res = await tokenPost(env, {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://client.example/callback",
      client_id: clientId,
      code_verifier: verifier,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      access_token: string;
      refresh_token?: string;
      scope: string;
    };
    expect(body.access_token).toContain(":");
    expect(body.scope).toBe("agent");

    const mcpRes = await worker.fetch(
      new Request(`${ORIGIN}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${body.access_token}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      }),
      env,
      {} as never,
    );
    expect(mcpRes.status).toBe(200);
    const mcpBody = (await mcpRes.json()) as { result: { tools: unknown[] } };
    expect(mcpBody.result.tools.length).toBe(6);
  });

  it("agent-scoped browser tokens cannot reach admin tools", async () => {
    const env = makeEnv();
    const { clientId, verifier, code } = await approvedCode(env, "agent");
    const tokenRes = await tokenPost(env, {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://client.example/callback",
      client_id: clientId,
      code_verifier: verifier,
    });
    const { access_token } = (await tokenRes.json()) as { access_token: string };
    const res = await worker.fetch(
      new Request(`${ORIGIN}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "export_dossier", arguments: { subjectId: "s" } },
        }),
      }),
      env,
      {} as never,
    );
    expect(res.status).toBe(403);
  });

  it("rejects a wrong PKCE verifier with RFC vocabulary", async () => {
    const env = makeEnv();
    const { clientId, code } = await approvedCode(env);
    const res = await tokenPost(env, {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://client.example/callback",
      client_id: clientId,
      code_verifier: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    const body = (await res.json()) as { error: string };
    expect(["invalid_grant", "invalid_request"]).toContain(body.error);
  });

  it("refresh_token grant issues a new access token through the shim", async () => {
    const env = makeEnv();
    const { clientId, verifier, code } = await approvedCode(env);
    const first = (await (
      await tokenPost(env, {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://client.example/callback",
        client_id: clientId,
        code_verifier: verifier,
      })
    ).json()) as { access_token: string; refresh_token: string };
    expect(first.refresh_token).toBeTruthy();

    const res = await tokenPost(env, {
      grant_type: "refresh_token",
      refresh_token: first.refresh_token,
      client_id: clientId,
    });
    expect(res.status).toBe(200);
    const second = (await res.json()) as { access_token: string };
    expect(second.access_token).toBeTruthy();
    expect(second.access_token).not.toBe(first.access_token);
  });

  it("applies per-IP and per-client caps before the library branch (condition 1)", async () => {
    const calls: string[] = [];
    const limit = vi.fn(async ({ key }: { key: string }) => {
      calls.push(key);
      return { success: !key.startsWith("tok:") };
    });
    const env = makeEnv({ APPROVAL_RATE_LIMITER: { limit } as unknown as RateLimit });
    const res = await tokenPost(
      env,
      { grant_type: "authorization_code", code: "x", client_id: "capped-client" },
      { "CF-Connecting-IP": "203.0.113.5" },
    );
    expect(res.status).toBe(429);
    expect(calls).toEqual(["tok-ip:203.0.113.5", "tok:capped-client"]);
  });

  it("fails closed (503, uniform vocabulary) for library grants without OAUTH_KV", async () => {
    const env = makeEnv({ OAUTH_KV: undefined });
    for (const grant_type of ["authorization_code", "refresh_token"]) {
      const res = await tokenPost(env, { grant_type, client_id: "x" });
      expect(res.status).toBe(503);
      expect(((await res.json()) as { error: string }).error).toBe("temporarily_unavailable");
      expect(res.headers.get("Cache-Control")).toBe("no-store");
    }
  });

  it("answers missing/unknown grant_type with unsupported_grant_type — never 404 (condition 2)", async () => {
    const env = makeEnv();
    for (const body of [
      {},
      { grant_type: "password" },
      { grant_type: "urn:ietf:params:oauth:grant-type:token-exchange" },
    ]) {
      const res = await tokenPost(env, body as Record<string, string>);
      expect(res.status).toBe(400);
      const json = (await res.json()) as { error: string };
      expect(json.error).toBe("unsupported_grant_type");
    }
  });

  it("forwards the RFC 7009 revocation shape (token, no grant_type) to the library", async () => {
    const env = makeEnv();
    const { clientId } = await approvedCode(env);
    const res = await tokenPost(env, { token: "whatever", client_id: clientId });
    // RFC 7009 §2.2: revocation answers 200 even for unknown tokens. The point here is the
    // shim did NOT classify this advertised shape as unsupported_grant_type.
    expect(res.status).toBe(200);
  });

  it("refuses non-form content types uniformly (condition 3 — single buffered body)", async () => {
    const env = makeEnv();
    const res = await worker.fetch(
      new Request(`${ORIGIN}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ grant_type: "authorization_code" }),
      }),
      env,
      {} as never,
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });

  it("treats browser-shaped Bearer tokens on /mcp as unverifiable without OAUTH_KV (503)", async () => {
    const env = makeEnv({ OAUTH_KV: undefined });
    const res = await worker.fetch(
      new Request(`${ORIGIN}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer a:b:c" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      }),
      env,
      {} as never,
    );
    expect(res.status).toBe(503);
  });

  it("rejects garbage browser-shaped tokens with a uniform 401", async () => {
    const env = makeEnv();
    const res = await worker.fetch(
      new Request(`${ORIGIN}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer a:b:c" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      }),
      env,
      {} as never,
    );
    expect(res.status).toBe(401);
  });
});
