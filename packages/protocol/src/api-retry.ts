export * as ApiRetry from "./api-retry.js";

/**
 * Retries of a failed API request, shared by both clients: capped exponential
 * backoff with jitter. See `docs/protocol.md` and `spec/vectors/api-retry.json`.
 */

export const RETRY_BASE_MS = 250;
export const RETRY_MAX_MS = 8000;
export const RETRIES = 6;

/**
 * How safely a request may be sent again after a failure. `idempotent`
 * requests (reads, binding the same CSR) are retried on any transient failure;
 * `once` requests (creating or deleting a tunnel) only when they cannot have
 * reached the API.
 */
export type Repeat = "idempotent" | "once";

/** Whether a response with `status` is a transient failure worth retrying. */
export const retryableStatus = (status: number, repeat: Repeat): boolean =>
  repeat === "idempotent"
    ? status === 429 || (status >= 500 && status <= 599)
    : // Rate limited, the API's own "unavailable", or Cloudflare could not reach the server at all.
      [429, 503, 521, 522, 523, 525].includes(status);

/**
 * The delay range in milliseconds before retry `attempt` (from 0):
 * `RETRY_BASE_MS` doubling up to `RETRY_MAX_MS`, between half of that and all
 * of it. A `Retry-After` in seconds is followed instead, up to `RETRY_MAX_MS`.
 */
export const retryDelayMs = (attempt: number, retryAfter?: string | null): readonly [number, number] => {
  const seconds = retryAfter?.trim();
  if (seconds && /^\d+$/.test(seconds)) {
    const delay = Math.min(Number(seconds) * 1000, RETRY_MAX_MS);
    return [delay, delay];
  }
  const delay = Math.min(RETRY_BASE_MS * 2 ** Math.min(attempt, 16), RETRY_MAX_MS);
  return [delay / 2, delay];
};

const CLOUDFLARE_REASONS: Record<number, string> = {
  520: "the server returned an unknown error",
  521: "the server refused the connection",
  522: "the connection to the server timed out",
  523: "the server is unreachable",
  524: "the server did not answer in time",
  525: "the SSL handshake with the server failed",
  526: "the server's certificate is invalid",
  527: "the connection to the server failed",
};

/** What Cloudflare, which proxies the hosted API, means by its own 52x statuses. */
export const cloudflareReason = (status: number): string | undefined => CLOUDFLARE_REASONS[status];

/** The message for an error response without an API error body. */
export const statusMessage = (status: number, body: string): string => {
  const reason = cloudflareReason(status);
  if (reason) return `Cloudflare ${status}: ${reason}`;
  const trimmed = body.trim();
  return trimmed ? Array.from(trimmed).slice(0, 200).join("") : `HTTP ${status}`;
};
