import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type * as Tls from "node:tls";
import { Effect, Exit, Fiber, ManagedRuntime, Scope } from "effect";
import { OpenTunnelClient, OpenTunnelStorage as EffectStorage } from "../src/effect/index.js";
import {
  create,
  isValidRouteName,
  OpenTunnelClientError,
  OpenTunnelStorage,
  publicUrl,
  ROOT_ROUTE,
  ROUTE_LABEL_PATTERN,
  type OpenTunnelClientEvent,
  type OpenTunnelPromiseClient,
} from "../src/promise/index.js";
import { X509Certificate } from "node:crypto";
import {
  echoServer,
  fakeRelay,
  HOSTNAME,
  recordingServer,
  renewedCertificate,
  testIdentity,
  type FakeRelay,
} from "./fake-relay.js";
import { resolveRoute } from "../src/effect/tunnel.js";
import { Names } from "@opentunnel/protocol/names";
import { ProxyProtocol } from "@opentunnel/protocol/proxy-protocol";

let identity: Awaited<ReturnType<typeof testIdentity>>;
let relay: FakeRelay;
let echo: ReturnType<typeof echoServer>;
let client: OpenTunnelPromiseClient;
let store: ReturnType<typeof OpenTunnelStorage.memory>;

beforeEach(async () => {
  identity = await testIdentity();
  relay = fakeRelay(identity);
  echo = echoServer();
  store = OpenTunnelStorage.memory();
  await store.save("default", identity);
  client = create({ api: relay.url, store, ownerToken: "owner-secret" });
});

afterEach(async () => {
  await client.dispose();
  relay.stop();
  echo.stop();
});

const read = (socket: Tls.TLSSocket, bytes: number) =>
  new Promise<string>((resolve) => {
    let received = "";
    const onData = (data: Buffer) => {
      received += data.toString();
      if (received.length >= bytes) {
        socket.off("data", onData);
        resolve(received);
      }
    };
    socket.on("data", onData);
  });

const collect = (events: AsyncIterable<OpenTunnelClientEvent>) => {
  const seen: OpenTunnelClientEvent[] = [];
  void (async () => {
    for await (const event of events) seen.push(event);
  })();
  return seen;
};

describe("tunnel", () => {
  test("owner token is absent from tunnel API, bridge, and visitor URLs", async () => {
    const connection = await client.tunnel.connect({ routes: { api: echo.target } });
    await relay.next();
    expect(relay.requestAuthorizations.length).toBeGreaterThan(0);
    expect(relay.requestAuthorizations.every((request) => request.value !== "Bearer owner-secret")).toBe(true);
    expect(connection.urls.api).not.toContain("owner-secret");
    expect(publicUrl("api", HOSTNAME)).not.toContain("owner-secret");
    await connection.close();
  });

  test("forwards TLS to the route target", async () => {
    const connection = await client.tunnel.connect({ routes: { api: echo.target } });
    const session = await relay.next();
    expect(session.routes).toEqual(["api"]);

    const socket = await session.connectTls(7, `api.${HOSTNAME}`, identity.certificate);
    socket.write("hello");
    expect(await read(socket, 10)).toBe("echo:hello");

    const large = "x".repeat(200_000);
    const reply = read(socket, large.length);
    socket.write(large);
    const received = await reply;
    expect(received.replaceAll("echo:", "").length).toBe(large.length);

    expect(connection.status()).toMatchObject({ state: "connected", connections: 1 });
    socket.end();
    const closing = await Promise.race([session.next("end"), session.next("reset")]);
    expect(closing.conn).toBe(7);
    await connection.close();
  });

  test("serves the root route", async () => {
    const connection = await client.tunnel.connect({ routes: { "@": echo.target } });
    const session = await relay.next();
    const socket = await session.connectTls(1, HOSTNAME, identity.certificate);
    socket.write("root");
    expect(await read(socket, 9)).toBe("echo:root");
    await connection.close();
  });

  test("resets unknown routes", async () => {
    const connection = await client.tunnel.connect({ routes: { api: echo.target } });
    const session = await relay.next();
    session.open(3, `admin.${HOSTNAME}`);
    expect(await session.next("reset")).toEqual({ type: "reset", conn: 3, code: "unknown_route" });
    await connection.close();
  });

  test("resets connections beyond the advertised max_conns", async () => {
    const connection = await client.tunnel.connect({ routes: { api: echo.target } });
    const session = await relay.next();
    for (let conn = 1; conn <= 256; conn++) session.open(conn, `api.${HOSTNAME}`);
    session.open(257, `api.${HOSTNAME}`);
    expect(await session.next("reset")).toEqual({ type: "reset", conn: 257, code: "too_many_connections" });
    expect(connection.status().connections).toBe(256);
    await connection.close();
  });

  test("reconnects after the bridge closes", async () => {
    const connection = await client.tunnel.connect({ routes: { api: echo.target } });
    const events = collect(connection.events);
    (await relay.next()).close();
    await relay.next();
    expect(events.some((event) => event.type === "reconnecting")).toBe(true);
    await connection.close();
  });

  test("re-attaches only when route names change", async () => {
    const connection = await client.tunnel.connect({ routes: { api: echo.target } });
    await relay.next();

    await connection.setRoutes({ api: "127.0.0.1:9" });
    const reattached = relay.next();
    const early = await Promise.race([reattached.then(() => "attached"), Bun.sleep(300).then(() => "none")]);
    expect(early).toBe("none");
    expect(connection.status().routes).toEqual({ api: "127.0.0.1:9" });

    await connection.setRoutes({ api: echo.target, "@": echo.target });
    const session = await reattached;
    expect([...session.routes].sort()).toEqual(["@", "api"]);
    await connection.close();
  });

  test("rejects invalid routes before connecting", async () => {
    await expect(client.tunnel.connect({ routes: { api: "http://x" } })).rejects.toThrow("Invalid target");
    await expect(
      client.tunnel.connect({ routes: { api: { target: echo.target, proxyProtocol: "v3" as "v2" } } }),
    ).rejects.toThrow("Invalid proxyProtocol");
  });

  describe("route options", () => {
    const deliver = async (
      route: (target: string) => string | { target: string; proxyProtocol?: "v1" | "v2" },
      peer: string,
      payload: string,
      expected: number,
    ) => {
      const recorder = await recordingServer();
      try {
        const connection = await client.tunnel.connect({ routes: { api: route(recorder.target) } });
        const session = await relay.next();
        const socket = await session.connectTls(5, `api.${HOSTNAME}`, identity.certificate, peer);
        socket.write(payload);
        await recorder.received(expected);
        // Anything beyond what was expected would arrive within a moment.
        await Bun.sleep(50);
        await connection.close();
        return recorder.data();
      } finally {
        recorder.stop();
      }
    };

    test("default routes forward bytes unchanged", async () => {
      const payload = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
      for (const route of [(target: string) => target, (target: string) => ({ target })]) {
        const received = await deliver(route, "203.0.113.9:51234", payload, payload.length);
        expect(received.toString("latin1")).toBe(payload);
      }
    });

    test("writes a PROXY v1 header before the payload", async () => {
      const received = await deliver(
        (target) => ({ target, proxyProtocol: "v1" }),
        "203.0.113.9:51234",
        "hello",
        47,
      );
      expect(received.toString("latin1")).toBe("PROXY TCP4 203.0.113.9 0.0.0.0 51234 443\r\nhello");
    });

    test("writes a PROXY v2 header before the payload", async () => {
      const received = await deliver(
        (target) => ({ target, proxyProtocol: "v2" }),
        "[2001:db8::1]:443",
        "hello",
        16 + 36 + 3 + 13 + 5,
      );
      const header = ProxyProtocol.header("v2", "[2001:db8::1]:443", `api.${HOSTNAME}`);
      expect(received.subarray(0, 14)).toEqual(Buffer.from("0d0a0d0a000d0a515549540a2121", "hex"));
      expect(received.subarray(0, header.length)).toEqual(Buffer.from(header));
      expect(received.subarray(header.length).toString("latin1")).toBe("hello");
      expect(received.subarray(header.length - 13, header.length).toString("latin1")).toBe(`api.${HOSTNAME}`);
    });

    test("match the shared vectors", async () => {
      const vectors = await Bun.file(new URL("../../../spec/vectors/route-options.json", import.meta.url)).json();
      for (const { name, sdk, route, error } of vectors.routes) {
        if (error) {
          expect(() => resolveRoute(name, sdk)).toThrow();
          continue;
        }
        const resolved = resolveRoute(name, sdk);
        const target = Names.parseTarget(route.target)!;
        expect(resolved).toEqual(route.proxyProtocol ? { target, proxyProtocol: route.proxyProtocol } : { target });
      }
    });
  });

  test("fails on fatal attach errors", async () => {
    relay.attachError = "bad_token";
    await expect(client.tunnel.connect({ routes: { api: echo.target } })).rejects.toThrow();
  });

  test("picks up a certificate the server renewed while offline", async () => {
    const renewed = await renewedCertificate(identity.privateKey);
    relay.served = { certificate: renewed, chain: "" };
    const connection = await client.tunnel.connect({ routes: { api: echo.target } });
    expect(connection.tunnel.certificate).toBe(renewed);
    const saved = await store.load("default");
    expect(saved?.certificate).toBe(renewed);
    expect(saved?.privateKey).toBe(identity.privateKey);

    const session = await relay.next();
    const socket = await session.connectTls(5, `api.${HOSTNAME}`, renewed);
    const presented = new X509Certificate(socket.getPeerCertificate().raw);
    expect(presented.fingerprint256).toBe(new X509Certificate(renewed).fingerprint256);
    await connection.close();
  });
});

const waitFor = async (condition: () => boolean, timeoutMs = 5_000) => {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out waiting");
    await Bun.sleep(10);
  }
};

describe("connect signal", () => {
  test("an aborted signal rejects before connecting", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      client.tunnel.connect({ routes: { api: echo.target }, signal: controller.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(relay.sockets.opened).toBe(0);
    expect(relay.certificateRequests).toEqual([]);
  });

  test("aborts an attach the server never answers", async () => {
    relay.silent = true;
    const controller = new AbortController();
    const events: OpenTunnelClientEvent[] = [];
    const connecting = client.tunnel.connect({
      routes: { api: echo.target },
      signal: controller.signal,
      onEvent: (event) => events.push(event),
    });
    await waitFor(() => relay.sockets.opened === 1);
    const reason = new Error("gave up");
    controller.abort(reason);
    const started = Date.now();
    await expect(connecting).rejects.toBe(reason);
    expect(Date.now() - started).toBeLessThan(1_000);
    await waitFor(() => relay.sockets.closed === 1);
    expect(events.at(-1)).toEqual({ type: "stopped" });
    // Nothing reconnects after the abort.
    await Bun.sleep(300);
    expect(relay.sockets.opened).toBe(1);
  });

  test("aborts certificate work started by connect", async () => {
    relay.hangCertificate = true;
    const controller = new AbortController();
    const connecting = client.tunnel.connect({ routes: { api: echo.target }, signal: controller.signal });
    await waitFor(() => relay.certificateRequests.length === 1);
    controller.abort();
    await expect(connecting).rejects.toMatchObject({ name: "AbortError" });
    expect(relay.sockets.opened).toBe(0);
  });

  test("closes the connection when aborted after connecting", async () => {
    const controller = new AbortController();
    const connection = await client.tunnel.connect({ routes: { api: echo.target }, signal: controller.signal });
    controller.abort();
    await connection.closed;
    expect(connection.status().state).toBe("stopped");
  });
});

describe("route conflicts", () => {
  test("retry by default and report each conflict", async () => {
    relay.attachError = "route_conflict";
    const events: OpenTunnelClientEvent[] = [];
    const connecting = client.tunnel.connect({
      routes: { web: echo.target, api: echo.target },
      onEvent: (event) => events.push(event),
    });
    await waitFor(() => events.filter((event) => event.type === "route-conflict").length >= 2);
    expect(events.find((event) => event.type === "route-conflict")).toEqual({
      type: "route-conflict",
      routes: ["api", "web"],
    });
    relay.attachError = undefined;
    const connection = await connecting;
    expect(connection.status().state).toBe("connected");
    await connection.close();
  });

  test("fail connect with code route_conflict when asked to", async () => {
    relay.attachError = "route_conflict";
    const events: OpenTunnelClientEvent[] = [];
    const error = await client.tunnel
      .connect({ routes: { api: echo.target }, onRouteConflict: "fail", onEvent: (event) => events.push(event) })
      .catch((error: unknown) => error);
    expect(error).toBeInstanceOf(OpenTunnelClientError);
    expect(error).toMatchObject({ code: "route_conflict" });
    expect((error as Error).message).toContain("route_conflict");
    expect(relay.sockets.opened).toBe(1);
    expect(events.map((event) => event.type)).toEqual(["connecting", "route-conflict", "stopped"]);
  });

  test("stop the tunnel on a later conflict when asked to fail", async () => {
    const connection = await client.tunnel.connect({ routes: { api: echo.target }, onRouteConflict: "fail" });
    await relay.next();
    relay.attachError = "route_conflict";
    await connection.setRoutes({ api: echo.target, web: echo.target });
    await expect(connection.closed).rejects.toMatchObject({ code: "route_conflict" });
  });

  test("other fatal attach errors carry their code", async () => {
    relay.attachError = "bad_token";
    await expect(client.tunnel.connect({ routes: { api: echo.target } })).rejects.toMatchObject({
      code: "bad_token",
    });
  });
});

describe("urls", () => {
  test("map each route to its public URL and follow setRoutes", async () => {
    const connection = await client.tunnel.connect({ routes: { api: echo.target, "@": echo.target } });
    expect(connection.urls).toEqual({ api: `https://api.${HOSTNAME}`, "@": `https://${HOSTNAME}` });
    await connection.setRoutes({ web: echo.target });
    expect(connection.urls).toEqual({ web: `https://web.${HOSTNAME}` });
    await connection.close();
  });

  test("publicUrl builds the same URLs", () => {
    expect(publicUrl("api", HOSTNAME)).toBe(`https://api.${HOSTNAME}`);
    expect(publicUrl(ROOT_ROUTE, HOSTNAME)).toBe(`https://${HOSTNAME}`);
  });
});

describe("route name validation", () => {
  test("is exported and matches the shared vectors", async () => {
    const vectors = await Bun.file(new URL("../../../spec/vectors/names.json", import.meta.url)).json();
    for (const { value, valid } of vectors.route as Array<{ value: string; valid: boolean }>) {
      expect([value, isValidRouteName(value)]).toEqual([value, valid]);
      if (value !== ROOT_ROUTE) expect([value, ROUTE_LABEL_PATTERN.test(value)]).toEqual([value, valid]);
    }
  });

  test("is the rule connect enforces", async () => {
    expect(isValidRouteName("Api")).toBe(false);
    await expect(client.tunnel.connect({ routes: { Api: echo.target } })).rejects.toThrow("Invalid route name 'Api'");
  });
});

describe("ensure progress", () => {
  test("reports checking then ready for a tunnel with a current certificate", async () => {
    const stages: string[] = [];
    await client.tunnel.ensure({ onProgress: (stage) => stages.push(stage) });
    expect(stages).toEqual(["checking-certificate", "ready"]);
  });

  test("reports saving a certificate the server renewed", async () => {
    relay.served = { certificate: await renewedCertificate(identity.privateKey), chain: "" };
    const stages: string[] = [];
    await client.tunnel.ensure({ onProgress: (stage) => stages.push(stage) });
    expect(stages).toEqual(["checking-certificate", "saving-identity", "ready"]);
  });

  test("reports issuing a new certificate after a failed one", async () => {
    relay.states.push({ type: "failed", reason: "test" });
    const stages: string[] = [];
    const ensured = await client.tunnel.ensure({ onProgress: (stage) => stages.push(stage) });
    expect(stages).toEqual([
      "checking-certificate",
      "generating-key",
      "generating-csr",
      "requesting-certificate",
      "waiting-certificate",
      "saving-identity",
      "ready",
    ]);
    expect(relay.certificateRequests).toEqual(["GET", "POST", "GET"]);
    expect(ensured.privateKey).not.toBe(identity.privateKey);
  });
});

describe("effect connect", () => {
  test("interrupting it while it attaches stops the tunnel before the scope closes", async () => {
    relay.silent = true;
    const storage = EffectStorage.memory();
    await Effect.runPromise(storage.save("default", identity));
    const runtime = ManagedRuntime.make(OpenTunnelClient.layer({ api: relay.url, storage }));
    try {
      const scope = await runtime.runPromise(Scope.make());
      const fiber = runtime.runFork(
        Effect.flatMap(OpenTunnelClient, (client) => client.tunnel.connect({ routes: { api: echo.target } })).pipe(
          Effect.provideService(Scope.Scope, scope),
        ),
      );
      await waitFor(() => relay.sockets.opened === 1);
      await runtime.runPromise(Fiber.interrupt(fiber));
      await waitFor(() => relay.sockets.closed === 1);
      await runtime.runPromise(Scope.close(scope, Exit.void));
    } finally {
      await runtime.dispose();
    }
  });
});
