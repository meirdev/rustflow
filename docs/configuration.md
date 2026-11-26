# Configuration File

`rustflow collect` can take its settings from a TOML file instead of, or together with, its
flags:

```bash
rustflow collect --config /etc/rustflow/rustflow.toml
```

Everything a flag sets can be set in the file. Extra fields, enrichment and inline custom
elements can only be set there.

## Example

```toml
recv_buffer = 8388608
template_timeout = "20m"

[[input]]
url = "netflow://:9995"

[[input]]
url = "sflow://:6343"

[output]
format = "common"
serialization = "parquet"
path = "/var/lib/rustflow"
fields = ["time_received_ns", "src_addr", "dst_addr", "bytes", "packets", "vrf", "src_asn"]

[output.rotation]
interval = "5m"
level = 2
expire = "30d"

[metrics]
host = "127.0.0.1"
port = 9090

[[element]]
enterprise = 9
id = 12235
name = "applicationName"
type = "string"

[[extra_field]]
name = "vrf"
element = "ingressVRFID"
number = 1000

[[enrich]]
type = "exact"
source = "vrfs.csv"
key_columns = ["exporter", "id"]
reload = "10m"

[[enrich.lookup]]
keys = ["sampler_address", "vrf"]
fields = [{ column = "name", name = "vrf_name" }]

[[enrich]]
type = "prefix_lookup"
source = "GeoLite2-ASN.mmdb"

[[enrich.lookup]]
keys = ["src_addr"]
fields = [{ column = "autonomous_system_number", name = "src_asn", type = "unsigned" }]
```

## Flags and the file together

A flag replaces the file's setting, so one file can serve several runs:

```bash
rustflow collect --config rustflow.toml --serialization csv --output flows.csv
```

`--input` and `--fields` replace the file's lists; they do not add to them.

## Paths

A relative path in the file is relative to the file, not to the directory `rustflow` is started
from. A configuration and the tables it names can then be moved together. This holds for
`ie_mapping`, `output.path`, an enrichment's `source` and `command`, and the capture of a
`+pcap://` input.

## Keys

A key that is not listed here is an error, as is a value of the wrong type; the message gives
the line and column.

### Top level

| Key                | Flag                 | Default   |
| ------------------ | -------------------- | --------- |
| `recv_buffer`      | `--recv-buffer`      | `4194304` |
| `template_timeout` | `--template-timeout` | `600`     |
| `ie_mapping`       | `--ie-mapping`       |           |

A duration is a number of seconds, or a string with a unit such as `"20m"` or `"30d"`.

### `[[input]]`

| Key   | Flag      |
| ----- | --------- |
| `url` | `--input` |

Repeat the table for each input. See [Network Input](collector.md#network-input) for the URLs.

### `[output]`

| Key             | Flag              | Default  |
| --------------- | ----------------- | -------- |
| `format`        | `--format`        | `raw`    |
| `serialization` | `--serialization` | `ndjson` |
| `path`          | `--output`        | stdout   |
| `fields`        | `--fields`        | all      |

### `[output.rotation]`

| Key           | Flag            | Default |
| ------------- | --------------- | ------- |
| `interval`    | `--interval`    |         |
| `level`       | `--level`       |         |
| `hive`        | `--hive`        | `false` |
| `prefix`      | `--prefix`      | `flows` |
| `exec`        | `--exec`        |         |
| `expire`      | `--expire`      |         |
| `expire_exec` | `--expire-exec` |         |

See [Output](output.md#file-rotation) for what they do.

### `[metrics]`

| Key    | Flag             | Default   |
| ------ | ---------------- | --------- |
| `host` | `--metrics-host` | `0.0.0.0` |
| `port` | `--metrics-port` | `9090`    |

### `[[element]]`

A custom Information Element, as a row of the [`--ie-mapping`](collector.md#custom-information-elements)
file. Both can be used; the file's elements are added after the CSV's.

| Key          | Meaning                                     |
| ------------ | ------------------------------------------- |
| `id`         | The element's ID                            |
| `enterprise` | Its enterprise number; leave out for IANA's |
| `name`       | Its name                                    |
| `type`       | Its data type, such as `unsigned32`         |

### `[[extra_field]]`

An [extra field](collector.md#extra-fields).

| Key       | Meaning                                                     |
| --------- | ----------------------------------------------------------- |
| `name`    | The column's name                                           |
| `element` | The element: a name, an ID or `"enterprise/ID"`             |
| `number`  | Optional. The field's [protobuf number](output.md#protobuf) |

### `[[enrich]]`

An [enrichment](enrichment.md) source, with a `[[enrich.lookup]]` for each key it is looked up
by.

| Key           | Meaning                                                            |
| ------------- | ------------------------------------------------------------------ |
| `type`        | `"prefix_lookup"` or `"exact"`                                     |
| `source`      | A CSV or MMDB file                                                 |
| `command`     | An executable that prints CSV, instead of `source`                 |
| `timeout`     | How long the command may run; `"30s"` by default                   |
| `format`      | `"csv"` or `"mmdb"`; from the file's extension unless given        |
| `key_columns` | The CSV columns that hold the key, one for each key of a lookup    |
| `reload`      | `"never"` (default), an interval of at least `"10s"`, or `"watch"` |

`[[enrich.lookup]]`:

| Key      | Meaning                                                                             |
| -------- | ----------------------------------------------------------------------------------- |
| `keys`   | The fields that form the key: common flow fields or extra fields                    |
| `fields` | The outputs: `column` of the source, `name` of the field, optional `type`, `number` |

A `type` is `"string"` (default), `"unsigned"`, `"signed"`, `"float"`, `"boolean"` or
`"timestamp"`.
