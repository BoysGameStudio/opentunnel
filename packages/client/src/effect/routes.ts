import { Names } from "@opentunnel/protocol/names";
import type { OpenTunnelRoutes, OpenTunnelUrls } from "./types.js";

/** The route name for the tunnel hostname itself. */
export const ROOT_ROUTE = Names.ROOT_ROUTE;

/** A route name other than `@`: one lowercase DNS label. */
export const ROUTE_LABEL_PATTERN = Names.LABEL_PATTERN;

/** Whether `name` is a valid route name: `@` or one lowercase DNS label. */
export const isValidRouteName = (name: string): boolean => Names.isValidRoute(name);

/** The public URL of a route on a tunnel hostname. */
export const publicUrl = (route: string, hostname: string): string =>
  `https://${Names.publicHostname(route, hostname)}`;

/** The public URL of each route on a tunnel hostname. */
export const publicUrls = (routes: OpenTunnelRoutes, hostname: string): OpenTunnelUrls =>
  Object.fromEntries(Object.keys(routes).map((route) => [route, publicUrl(route, hostname)]));
