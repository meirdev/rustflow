FROM ubuntu:focal

RUN apt update && apt install -y ca-certificates curl build-essential libpcap-dev

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs --output rustup.sh && \
    sh rustup.sh -y && \
    rm rustup.sh

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
