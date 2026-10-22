import type { Effect, Scope, Stream } from "effect";
import type { OpenTunnelError } from "./errors.js";

export interface OpenTunnelProfileOptions {
  readonly profile?: string;
}

export type OpenTunnelProvisionStage =
  /** `ensure` found a stored tunnel and is checking its certificate with the server. */
  | "checking-certificate"
  | "creating-tunnel"
  | "generating-key"
  | "generating-csr"
  | "resuming-certificate"
  | "requesting-certificate"
  | "waiting-certificate"
  | "saving-identity"
  | "ready";

/** PROXY protocol version a route sends to its target before any payload. */
export type OpenTunnelProxyProtocol = "v1" | "v2";

/** A route target with options. */
export interface OpenTunnelRoute {
  /** `host:port` of the local service. */
  readonly target: string;
  /**
   * Writes a PROXY protocol header carrying the visitor's address to the
   * target before each connection's data. Only enable it for targets that
   * expect one.
   */
  readonly proxyProtocol?: OpenTunnelProxyProtocol;
}

/**
 * Route name (`@` for the tunnel hostname, or a subdomain label) to its
 * `host:port` target, or to a target with options.
 */
export type OpenTunnelRoutes = Readonly<Record<string, string | OpenTunnelRoute>>;

/** Called with each step of creating a tunnel or getting its certificate. */
export interface OpenTunnelProgressOptions {
  readonly onProgress?: (stage: OpenTunnelProvisionStage) => void;
}

/** Public URL of each route: `https://<route>.<hostname>`, or `https://<hostname>` for `@`. */
export type OpenTunnelUrls = Readonly<Record<string, string>>;

export interface OpenTunnelIdentity {
  readonly id: string;
  readonly hostname: string;
  readonly token: string;
  readonly privateKey: string;
  readonly certificate: string;
  readonly chain: string;
  readonly certificateExpiry: Date;
}

export interface OpenTunnelPendingIdentity {
  readonly id: string;
  readonly hostname: string;
  readonly token: string;
  readonly privateKey: string;
  readonly csr: string;
}

export interface OpenTunnelStoredTunnel {
  readonly profile: string;
  readonly tunnel: OpenTunnelIdentity;
}

export type OpenTunnelClientEvent =
  | { readonly type: "connecting"; readonly attempt: number }
  | { readonly type: "connected"; readonly session: string; readonly routes: ReadonlyArray<string> }
  | { readonly type: "disconnected"; readonly reason: string }
  | { readonly type: "reconnecting"; readonly attempt: number; readonly delayMs: number }
  /**
   * Another bridge holds a route (`attach_error` `route_conflict`). `routes`
   * are the ones this attach claimed: the server does not say which is held.
   */
  | { readonly type: "route-conflict"; readonly routes: ReadonlyArray<string> }
  | { readonly type: "connection-opened"; readonly conn: number; readonly route: string; readonly peer: string }
  | { readonly type: "connection-closed"; readonly conn: number; readonly route: string; readonly error?: string }
  | { readonly type: "certificate-renewed"; readonly expiry: string }
  | { readonly type: "stopped"; readonly error?: string };

export interface OpenTunnelStatus {
  readonly state: "waiting-routes" | "connecting" | "connected" | "reconnecting" | "stopped";
  readonly hostname: string;
  readonly routes: OpenTunnelRoutes;
  readonly session?: string;
  readonly connections: number;
  readonly lastError?: string;
  /** Unix milliseconds of the last successful attach. */
  readonly connectedAt?: number;
}

export interface OpenTunnelConnectOptions extends OpenTunnelProfileOptions {
  readonly routes: OpenTunnelRoutes;
  /**
   * What to do when another bridge holds a route. `"retry"` (the default)
   * retries with backoff, taking the route over once the other bridge goes
   * away. `"fail"` stops the tunnel: `connect` fails with code
   * `route_conflict`, or `closed` does if the conflict happens on a later
   * attach. Both emit `route-conflict` first.
   */
  readonly onRouteConflict?: "retry" | "fail";
  /**
   * Called with every event as it happens, including those before `connect`
   * completes (such as `route-conflict` while it retries), which `events`
   * cannot deliver yet.
   */
  readonly onEvent?: (event: OpenTunnelClientEvent) => void;
}

export interface OpenTunnelConnection {
  readonly tunnel: OpenTunnelIdentity;
  readonly events: Stream.Stream<OpenTunnelClientEvent>;
  readonly status: Effect.Effect<OpenTunnelStatus>;
  /** The public URL of each current route; follows `setRoutes`. */
  readonly urls: Effect.Effect<OpenTunnelUrls>;
  readonly setRoutes: (routes: OpenTunnelRoutes) => Effect.Effect<void, OpenTunnelError>;
  /** Completes when the tunnel stops after a fatal error or is closed. */
  readonly closed: Effect.Effect<void, OpenTunnelError>;
  readonly close: Effect.Effect<void>;
}

export interface OpenTunnelEffectClient {
  readonly profile: {
    readonly list: () => Effect.Effect<ReadonlyArray<string>, OpenTunnelError>;
  };
  readonly tunnel: {
    readonly list: () => Effect.Effect<ReadonlyArray<OpenTunnelStoredTunnel>, OpenTunnelError>;
    readonly get: (
      options?: OpenTunnelProfileOptions,
    ) => Effect.Effect<OpenTunnelIdentity | undefined, OpenTunnelError>;
    readonly pending: (
      options?: OpenTunnelProfileOptions,
    ) => Effect.Effect<Pick<OpenTunnelPendingIdentity, "id" | "hostname"> | undefined, OpenTunnelError>;
    readonly resume: (
      options?: OpenTunnelProfileOptions & {
        readonly onProgress?: (stage: OpenTunnelProvisionStage) => void;
      },
    ) => Effect.Effect<OpenTunnelIdentity | undefined, OpenTunnelError>;
    readonly create: (
      options?: OpenTunnelProfileOptions & {
        readonly onProgress?: (stage: OpenTunnelProvisionStage) => void;
      },
    ) => Effect.Effect<OpenTunnelIdentity, OpenTunnelError>;
    readonly ensure: (
      options?: OpenTunnelProfileOptions & OpenTunnelProgressOptions,
    ) => Effect.Effect<OpenTunnelIdentity, OpenTunnelError>;
    readonly remove: (
      options?: OpenTunnelProfileOptions,
    ) => Effect.Effect<void, OpenTunnelError>;
    /**
     * Starts forwarding routes for the profile's tunnel, creating it if
     * needed. Succeeds once the bridge first attaches and keeps reconnecting
     * until the scope closes. Interrupting it while it attaches stops the
     * tunnel and any certificate work it started.
     */
    readonly connect: (
      options: OpenTunnelConnectOptions,
    ) => Effect.Effect<OpenTunnelConnection, OpenTunnelError, Scope.Scope>;
  };
}
