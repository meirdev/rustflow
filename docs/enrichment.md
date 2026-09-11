# Enrichment

RustFlow enriches normalized flows from CSV or MaxMind DB (`.mmdb`) files.

Use `-f common` and one `--enrich` argument per source.

## Parameters

Each `--enrich` argument is a comma-separated list of `key=value` parameters.

| Parameter    | Description                                                                            |
| ------------ | -------------------------------------------------------------------------------------- |
| `type`       | Required. `prefix_lookup` (longest-prefix match) or `exact` (CSV only).                |
| `source`     | Required. Source file path.                                                            |
| `format`     | `csv` or `mmdb`; inferred from the extension unless specified.                         |
| `fields`     | Required. `<key>@<source>:<output>[\|<source>:<output>...]`; separate groups with `;`. |
| `key_column` | CSV key column. Required for CSV; not allowed for MMDB.                                |
| `reload`     | `never` (default), an interval of at least `10s`, or `watch`.                          |

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
