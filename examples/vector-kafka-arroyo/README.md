# rustflow → Vector → Kafka → Arroyo → Kafka

A Docker Compose example of a streaming flow-analytics pipeline:

```text
IPFIX / NetFlow (UDP 9995)
        │
        ▼
    rustflow collect -f common -s protobuf     ┐
        │  length-delimited protobuf (stdout)  │ one container
        ▼                                      │ (Vector `exec` source)
      Vector  ── decode protobuf, JSON ──►     ┘
        │
        ▼
   Kafka topic `flows`          (one JSON message per flow)
        │
        ▼
      Arroyo  (pipeline.sql: sliding top-talker windows, 60 s wide every 10 s)
        │
        ▼
   Kafka topic `flow-stats`     (one JSON message per window × src/dst/proto)
```

> Demonstration only. Single-node Kafka, no persistence, no auth.

## Files

| file | purpose |
|---|---|
| `docker-compose.yml` | the stack: `collector` (rustflow + Vector), `generator`, `kafka`, `kafka-init`, `arroyo` |
| `Dockerfile` | builds rustflow from this repository on top of the official Vector image |
| `vector.yaml` | runs rustflow, decodes its protobuf output, produces JSON to Kafka |
| `rustflow.desc` | compiled protobuf descriptor Vector needs (see below) |
| `pipeline.sql` | the Arroyo SQL pipeline (hopping-window top talkers), run with `arroyo run` |

## Start

From this directory:

```bash
docker compose up -d --build
```

The first build compiles rustflow from source and takes a few minutes.

The `generator` service sends synthetic IPFIX to the collector straight away,
so all topics fill up on their own. To feed real exporters instead, point them
at UDP port 9995 of the Docker host and stop the generator:

```bash
docker compose stop generator
```

## Look at the data

Raw flows as Vector produced them:

```bash
docker compose exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic flows --from-beginning --max-messages 5
```

Windowed aggregates from Arroyo (the first window closes after ~60 s, then one every 10 s):

```bash
docker compose exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic flow-stats --from-beginning --max-messages 5
```

Kafka is also reachable from the host at `localhost:9094`.

Arroyo's dashboard for the running pipeline is at <http://localhost:5115>.

## How the pieces fit

**rustflow → Vector.** rustflow writes protobuf `CommonFlow` messages, each
prefixed with its length as a varint, to stdout. Vector's `exec` source runs it
and decodes the stream with `framing.method: varint_length_delimited` and the
`protobuf` codec (Vector 0.58 or later). A `remap` transform turns the binary
addresses into strings and the nanosecond timestamp into RFC 3339, then the
`kafka` sink writes JSON. See [docs/vector.md](../../docs/vector.md) for the
same setup outside Docker.

**Arroyo.** `pipeline.sql` declares the `flows` topic as a JSON source table and
`flow-stats` as a JSON sink table, then inserts a hopping-window aggregate:
60 seconds wide, sliding every 10 seconds. The width is chosen to cover an
exporter's active timeout, since a flow record reports traffic accumulated
since the previous report rather than traffic at an instant. Because the
windows overlap, one flow contributes to six consecutive rows; do not sum
`flow-stats` rows across windows. Use `TUMBLE(INTERVAL '10 seconds')` instead
if you need non-overlapping per-interval totals.
`arroyo run` executes that one file as a self-contained local cluster, so no
separate database or pipeline submission step is needed. Edit the SQL and
`docker compose restart arroyo` to try a different query.

## Regenerating `rustflow.desc`

Vector decodes protobuf from a compiled `FileDescriptorSet`. If
`crates/rustflow_collect/proto/rustflow.proto` changes, rebuild it from the
repository root:

```bash
uvx --from grpcio-tools python -m grpc_tools.protoc \
    -I crates/rustflow_collect/proto \
    -o examples/vector-kafka-arroyo/rustflow.desc \
    crates/rustflow_collect/proto/rustflow.proto
```

## Stop

```bash
docker compose down
```
