# syntax=docker/dockerfile:1
# The hosted service: crates/opentunnel-server and the website it serves. See fly.toml and docs/server.md.
# Base images are pinned by digest; update a tag and its digest together (docker buildx imagetools inspect <image>).

FROM oven/bun:1.4.2@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895 AS website
WORKDIR /src
COPY package.json bun.lock bunfig.toml tsconfig.base.json index.html vite.config.ts ./
COPY packages ./packages
RUN bun install --frozen-lockfile
RUN bunx vite build

FROM rust:1-bookworm@sha256:e12566d5abc17a0da741628782cdb504b68b8961f5bfcf677936bf3e8b32de29 AS server
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p opentunnel-server \
    && cp target/release/opentunnel-server /usr/local/bin/opentunnel-server

FROM gcr.io/distroless/cc-debian12@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa
COPY --from=server /usr/local/bin/opentunnel-server /usr/local/bin/opentunnel-server
COPY --from=website /src/dist/website /app/website
ENV WEBSITE_DIR=/app/website \
    TLS_LISTEN=[::]:8443 \
    HTTP_LISTEN=[::]:8080
EXPOSE 8443 8080
ENTRYPOINT ["/usr/local/bin/opentunnel-server"]
