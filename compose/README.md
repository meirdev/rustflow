# RustFlow Docker Compose Example

This directory provides a Docker Compose environment for quickly testing RustFlow and exploring collected flow data with ClickHouse and Grafana.

> **This setup is intended for testing and demonstration purposes only. It is not intended for production use.**

## Overview

The example provides a simple flow analytics pipeline:

```text
NetFlow / IPFIX / sFlow
          │
          ▼
      RustFlow
          │
          ▼
    Parquet files
          │
          ▼
      ClickHouse
          │
          ▼
       Grafana
```

RustFlow writes normalized flows directly to Parquet files.

ClickHouse queries the Parquet files directly and **does not ingest or store the flow data**. Grafana uses ClickHouse as its data source to visualize the flows.

This makes it easy to try RustFlow and inspect the collected traffic without setting up a complete flow storage pipeline.

## Start

From this directory, run:

```bash
docker compose up -d
```

Open Grafana at:

`http://localhost:3000`

## Send Flows

Send NetFlow or IPFIX traffic to the RustFlow collector.

For example, you can use the RustFlow generator:

```bash
rustflow generate -H 127.0.0.1 -p 9995
```

## Stop

Stop the environment with:

```bash
docker compose down
```
