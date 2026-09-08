# rustflow + Vector in one image: Vector's `exec` source runs the collector
# and decodes its protobuf stdout stream (see docs/vector.md).
# Build context is the repository root.
FROM rust:1-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p rustflow_cli && strip target/release/rustflow

# Vector 0.58.0 or later is required for `varint_length_delimited` framing.
FROM timberio/vector:0.58.0-debian
COPY --from=build /src/target/release/rustflow /usr/local/bin/rustflow
