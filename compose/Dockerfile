FROM rust:1-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p rustflow_cli && strip target/release/rustflow

FROM debian:trixie-slim
COPY --from=build /src/target/release/rustflow /usr/local/bin/rustflow
ENTRYPOINT ["rustflow"]
