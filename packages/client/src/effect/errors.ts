import { Schema } from "effect";

export class OpenTunnelClientError extends Schema.TaggedError<OpenTunnelClientError>()(
  "OpenTunnelClientError",
  {
    message: Schema.String,
    /** The bridge's `attach_error` code when attaching failed, such as `bad_token` or `route_conflict`. */
    code: Schema.optional(Schema.String),
    cause: Schema.optional(Schema.Defect()),
  },
) {}

export class OpenTunnelStorageError extends Schema.TaggedError<OpenTunnelStorageError>()(
  "OpenTunnelStorageError",
  { message: Schema.String, cause: Schema.optional(Schema.Defect()) },
) {}

export type OpenTunnelError = OpenTunnelClientError | OpenTunnelStorageError;
