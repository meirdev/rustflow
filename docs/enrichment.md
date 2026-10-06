# Enrichment

RustFlow enriches normalized flows from CSV or MaxMind DB (`.mmdb`) files, or from
CSV printed by a command.

Use `-f common` and one `--enrich` argument per source.

## Parameters

Each `--enrich` argument is a comma-separated list of `key=value` parameters.

| Parameter    | Description                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------- |
| `type`       | Required. `prefix_lookup` (longest-prefix match) or `exact` (CSV only).                                     |
| `source`     | Source file path. Either `source` or `command` is required.                                                 |
| `command`    | Path of an executable that prints the source as CSV. See [Command](#command).                               |
| `timeout`    | How long the command may run; `30s` by default. Only with `command`.                                        |
| `format`     | `csv` or `mmdb`; inferred from the file extension unless specified. A command is always `csv`.              |
| `fields`     | Required. `<key>@<source>:<output>[\|<source>:<output>...]`; separate groups with `;`.                      |
| `key_column` | CSV key column, or `+`-separated columns for a composite exact key. Required for CSV; not allowed for MMDB. |
| `reload`     | `never` (default), an interval of at least `10s`, or `watch` (files only).                                  |

### Fields

Use `@` after the lookup key, `|` between source-to-output mappings, and `;` between
lookup groups. For example:

```text
fields=src_addr@asn:src_asn|org:src_org;dst_addr@asn:dst_asn
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

```bash
rustflow collect -t netflow -p 9995 -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key_column=prefix,fields=dst_addr@prefix:dst_network"
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

```bash
rustflow collect -t netflow -p 9995 -f common \
  --enrich "type=exact,source=protocols.csv,key_column=number,fields=proto@name:proto_name"
```

#### Composite keys

Several flow fields can form one key by joining them with `+`, with a CSV column
for each in the same order. A row matches only when every column matches, and a
flow missing any of the fields is not enriched. Up to four fields can be combined.

Save this as `ifnames.csv`:

```csv
exporter,ifindex,name
10.0.0.1,1,uplink
10.0.0.1,2,lan
```

```bash
rustflow collect -t netflow -p 9995 -f common \
  --enrich "type=exact,source=ifnames.csv,key_column=exporter+ifindex,fields=sampler_address+in_if@name:in_if_name;sampler_address+out_if@name:out_if_name"
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

```bash
rustflow collect -t netflow -p 9995 -f common \
  --enrich "type=exact,command=/etc/rustflow/ifnames.sh,reload=10m,key_column=exporter+ifindex,fields=sampler_address+in_if@name:in_if_name;sampler_address+out_if@name:out_if_name"
```

The command must exit with status 0 within `timeout` and print at least one row.
Otherwise the load fails, and on a reload the previous data stays in use.

## MaxMind DB

MMDB supports only prefix lookups. Use dotted paths for nested fields:

```bash
rustflow collect -t netflow -p 9995 -f common \
  --enrich "type=prefix_lookup,source=GeoLite2-City.mmdb,fields=src_addr@country.iso_code:src_country|city.names.en:src_city"
```

Values of any type are emitted as strings; arrays and maps are rendered as JSON.

## Multiple enrichments

Repeat `--enrich` to combine sources:

```bash
rustflow collect -t netflow -p 9995 -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key_column=prefix,fields=dst_addr@asn:dst_asn|org:dst_org" \
  --enrich "type=prefix_lookup,source=GeoLite2-Country.mmdb,fields=dst_addr@country.iso_code:dst_country"
```
