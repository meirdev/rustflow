FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release -p rustflow_cli && strip target/release/rustflow

FROM alpine:3
COPY --from=build /src/target/release/rustflow /usr/local/bin/rustflow
ENTRYPOINT ["rustflow"]
