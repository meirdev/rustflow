# Enrichment

RustFlow enriches normalized flows from CSV or MaxMind DB (`.mmdb`) files, or from
CSV printed by a command.

Enrichment is set in the [configuration file](configuration.md), with an `[[enrich]]` table for
each source, and needs the common format:

```bash
rustflow collect --input netflow://:9995 -f common --config rustflow.toml
```

The examples below are what goes into `rustflow.toml`.

## Keys

| Key           | Description                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------- |
| `type`        | Required. `"prefix_lookup"` (longest-prefix match) or `"exact"` (CSV only).                       |
| `source`      | Source file path. Either `source` or `command` is required.                                       |
| `command`     | Path of an executable that prints the source as CSV. See [Command](#command).                     |
| `timeout`     | How long the command may run; `"30s"` by default. Only with `command`.                            |
| `format`      | `"csv"` or `"mmdb"`; inferred from the file extension unless given. A command is always CSV.      |
| `key_columns` | The CSV columns holding the key, one for each key of a lookup. Required for CSV; not for MMDB.    |
| `reload`      | `"never"` (default), an interval of at least `"10s"`, or `"watch"` (files only).                  |

A relative `source` or `command` is relative to the configuration file.

### Lookups

Each `[[enrich.lookup]]` under a source names the flow fields to look up by, and the fields the
match gives:

```toml
[[enrich]]
type = "prefix_lookup"
source = "asn.csv"
key_columns = ["prefix"]

[[enrich.lookup]]
keys = ["src_addr"]
fields = [
    { column = "asn", name = "src_asn" },
    { column = "org", name = "src_org" },
]

[[enrich.lookup]]
keys = ["dst_addr"]
fields = [{ column = "asn", name = "dst_asn" }]
```

`column` is the column of the source and `name` the output field. An output name cannot be the
name of a [common flow](output.md#common-flow) field, or of an
[extra field](collector.md#extra-fields).

### Extra fields as keys

A key is a common flow field or an [extra field](collector.md#extra-fields), by its name. This
reaches elements the common flow does not keep, such as a VRF:

```toml
[[extra_field]]
name = "vrf"
element = "ingressVRFID"

[[enrich]]
type = "exact"
source = "vrfs.csv"
key_columns = ["exporter", "id"]

[[enrich.lookup]]
keys = ["sampler_address", "vrf"]
fields = [{ column = "name", name = "vrf_name" }]
```

The extra field's element must be an unsigned integer or an IPv4 or IPv6 address. A flow whose
record lacks the element has no key, and gets nothing from that lookup.

### Types

An output is a string unless it is given a `type`: `"string"`, `"unsigned"`, `"signed"`,
`"float"`, `"boolean"` or `"timestamp"` (Unix nanoseconds). A typed output is a number in
NDJSON and a native column in Parquet and Arrow:

```toml
fields = [
    { column = "asn", name = "src_asn", type = "unsigned" },
    { column = "org", name = "src_org" },
]
```

A CSV cell that is not of its column's type fails the load, and a reload keeps the previous
table. A MaxMind DB value that is not of the type is left out.

`number` is the output's [protobuf field number](output.md#protobuf):

```toml
fields = [{ column = "asn", name = "src_asn", type = "unsigned", number = 1001 }]
```

## CSV

### Prefix lookup

Keys must be IPv4 or IPv6 CIDR prefixes. The most specific matching prefix wins.

Save this as `asn.csv`:

```csv
prefix,asn,org
1.0.0.0/24,13335,CLOUDFLARENET
1.0.16.0/24,2519,VECTANT ARTERIA Networks Corporation
```

```toml
[[enrich]]
type = "prefix_lookup"
source = "asn.csv"
key_columns = ["prefix"]

[[enrich.lookup]]
keys = ["dst_addr"]
fields = [{ column = "prefix", name = "dst_network" }]
```

For `1.0.0.1`, this produces `dst_network=1.0.0.0/24`.

### Exact lookup

Keys must be individual IP addresses or unsigned integers, matching the flow field's type.

Save this as `protocols.csv`:

```csv
number,name
6,tcp
17,udp
```

```toml
[[enrich]]
type = "exact"
source = "protocols.csv"
key_columns = ["number"]

[[enrich.lookup]]
keys = ["proto"]
fields = [{ column = "name", name = "proto_name" }]
```

#### Composite keys

Several flow fields can form one key, with a CSV column for each in the same order. A row
matches only when every column matches, and a flow missing any of the fields is not enriched.
Up to four fields can be combined.

Save this as `ifnames.csv`:

```csv
exporter,ifindex,name
10.0.0.1,1,uplink
10.0.0.1,2,lan
```

```toml
[[enrich]]
type = "exact"
source = "ifnames.csv"
key_columns = ["exporter", "ifindex"]

[[enrich.lookup]]
keys = ["sampler_address", "in_if"]
fields = [{ column = "name", name = "in_if_name" }]

[[enrich.lookup]]
keys = ["sampler_address", "out_if"]
fields = [{ column = "name", name = "out_if_name" }]
```

## Command

Use `command` instead of `source` to load the CSV an executable prints on standard
output. The executable takes no arguments.

Save this as `/etc/rustflow/ifnames.sh` and make it executable:

```sh
#!/bin/sh
set -eu

echo "exporter,ifindex,name"
for router in 10.0.0.1 10.0.0.2; do
  names=$(snmpwalk -v2c -c public -Oqs "$router" IF-MIB::ifName)
  echo "$names" | sed -n "s/^ifName\.\([0-9]*\) \(.*\)$/$router,\1,\2/p"
done
```

```toml
[[enrich]]
type = "exact"
command = "/etc/rustflow/ifnames.sh"
reload = "10m"
key_columns = ["exporter", "ifindex"]

[[enrich.lookup]]
keys = ["sampler_address", "in_if"]
fields = [{ column = "name", name = "in_if_name" }]

[[enrich.lookup]]
keys = ["sampler_address", "out_if"]
fields = [{ column = "name", name = "out_if_name" }]
```

The command must exit with status 0 within `timeout` and print at least one row.
Otherwise the load fails, and on a reload the previous data stays in use.

## MaxMind DB

MMDB supports only prefix lookups. Use dotted paths for nested fields:

```toml
[[enrich]]
type = "prefix_lookup"
source = "GeoLite2-City.mmdb"

[[enrich.lookup]]
keys = ["src_addr"]
fields = [
    { column = "country.iso_code", name = "src_country" },
    { column = "city.names.en", name = "src_city" },
]
```

A value is emitted as a string unless the output has a `type`; arrays and maps are rendered as
JSON.

## Multiple enrichments

Repeat `[[enrich]]` to combine sources:

```toml
[[enrich]]
type = "prefix_lookup"
source = "asn.csv"
key_columns = ["prefix"]

[[enrich.lookup]]
keys = ["dst_addr"]
fields = [{ column = "asn", name = "dst_asn" }, { column = "org", name = "dst_org" }]

[[enrich]]
type = "prefix_lookup"
source = "GeoLite2-Country.mmdb"

[[enrich.lookup]]
keys = ["dst_addr"]
fields = [{ column = "country.iso_code", name = "dst_country" }]
```
