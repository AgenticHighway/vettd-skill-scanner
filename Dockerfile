# Builds only the http-shim binary (crates/vettd-skill-scanner is a path
# dependency of it).
#
# NOTE(vettd-scanner-suite#12): this is the seam for the future single-image
# bundle — that image's build can COPY --from=this-image:tag
# /usr/local/bin/http-shim instead of rebuilding Rust from source.
FROM rust:1.85.1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p http-shim

FROM gcr.io/distroless/cc-debian12
# distroless has no shell/curl/wget, so there's no container HEALTHCHECK here
# — the suite's adapter-level available() health check covers readiness
# (an unreachable shim degrades that scanner's run to "skipped", not a suite
# failure). Swap to a debian-slim final stage if an in-container healthcheck
# becomes worth the larger image.
COPY --from=build /src/target/release/http-shim /usr/local/bin/http-shim
EXPOSE 8788
ENTRYPOINT ["/usr/local/bin/http-shim"]
