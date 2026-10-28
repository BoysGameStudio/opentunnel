import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { ApiRetry } from "@opentunnel/protocol/api-retry";
import { create, OpenTunnelStorage, type OpenTunnelPromiseClient } from "../src/promise/index.js";
import { testIdentity } from "./fake-relay.js";
import ownerAuthVector from "../../../spec/vectors/owner-auth.json" with { type: "json" };

/** Answers each request with the next status (an error page, `Retry-After: 0`), then with the identity's certificate. */
const flakyApi = (statuses: number[], certificate: () => string) => {
  const seen: string[] = [];
  const authorizations: Array<string | null> = [];
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(request) {
      const url = new URL(request.url);
      const status = statuses[seen.length];
      seen.push(`${request.method} ${url.pathname}`);
      authorizations.push(request.headers.get("authorization"));
      if (status !== undefined) {
        return new Response(`<html>error code: ${status}</html>`, {
          status,
          headers: { "content-type": "text/html", "retry-after": "0" },
        });
      }
      return Response.json({
        id: "cert",
        state: {
          type: "ready",
          certificate: certificate(),
          chain: "",
          expiry: new Date(Date.now() + 86_400_000).toISOString(),
        },
      });
    },
  });
  return { url: `http://127.0.0.1:${server.port}`, seen, authorizations, stop: () => server.stop(true) };
};

let identity: Awaited<ReturnType<typeof testIdentity>>;
let store: ReturnType<typeof OpenTunnelStorage.memory>;
let api: ReturnType<typeof flakyApi> | undefined;
let client: OpenTunnelPromiseClient | undefined;

const start = (statuses: number[]) => {
  api = flakyApi(statuses, () => identity.certificate);
  client = create({ api: api.url, store, ownerToken: "owner-secret" });
  return { api, client };
};

beforeEach(async () => {
  identity = await testIdentity();
  store = OpenTunnelStorage.memory();
  await store.save("default", identity);
});

afterEach(async () => {
  await client?.dispose();
  api?.stop();
});

describe("API requests", () => {
  test("are retried after transient failures", async () => {
    const { api, client } = start([525, 502, 429]);
    const ensured = await client.tunnel.ensure();
    expect(ensured.certificate).toBe(identity.certificate);
    expect(api.seen).toHaveLength(4);
  });

  test("are not retried after client errors", async () => {
    const { api, client } = start([401]);
    await expect(client.tunnel.ensure()).rejects.toThrow("Failed to read certificate");
    expect(api.seen).toHaveLength(1);
  });

  test("keep a valid saved certificate while the API keeps failing", async () => {
    const { api, client } = start(Array(20).fill(525));
    const ensured = await client.tunnel.ensure();
    expect(ensured.certificate).toBe(identity.certificate);
    expect(api.seen).toHaveLength(ApiRetry.RETRIES + 1);
  });

  test("fail with the HTTP status and Cloudflare's meaning of it", async () => {
    await store.save("default", { ...identity, certificateExpiry: new Date(Date.now() - 1000) });
    const { client } = start(Array(20).fill(525));
    await expect(client.tunnel.ensure()).rejects.toThrow(
      "Failed to read certificate: Cloudflare 525: the SSL handshake with the server failed (HTTP 525)",
    );
  });

  test("sends the owner credential only to creation, not tunnel bearer requests", async () => {
    expect(
      ownerAuthVector.requests.find((request) => request.path === "/api/tunnel")?.ownerAuthorization,
    ).toBe(true);
    expect(
      ownerAuthVector.requests.filter((request) => request.path !== "/api/tunnel").every((request) => !request.ownerAuthorization),
    ).toBe(true);
    const { api, client } = start([]);
    await client.tunnel.ensure();
    expect(api.authorizations).toEqual([`Bearer ${identity.token}`]);

    await store.remove("default");
    await expect(client.tunnel.create()).rejects.toThrow("Failed to create tunnel");
    expect(api.authorizations).toEqual([`Bearer ${identity.token}`, "Bearer owner-secret"]);
  });

  test("create a tunnel again only when the first attempt cannot have arrived", async () => {
    await store.remove("default");
    const { api, client } = start([525, 520]);
    await expect(client.tunnel.create()).rejects.toThrow(
      "Failed to create tunnel: Cloudflare 520: the server returned an unknown error (HTTP 520)",
    );
    expect(api.seen).toEqual(["POST /api/tunnel", "POST /api/tunnel"]);
  });
});
