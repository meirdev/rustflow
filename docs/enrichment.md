# Enrichment

RustFlow can enrich normalized flows using prefix lookups from CSV or MaxMind DB (`.mmdb`) files.

Enrichment is configured with `--enrich` and can be specified multiple times.

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=asn:dst_asn"
```

## Parameters

| Parameter | Description                                                      |
| --------- | ---------------------------------------------------------------- |
| `type`    | Lookup type. Currently `prefix_lookup`                           |
| `source`  | Path to a CSV or MaxMind DB (`.mmdb`) file                       |
| `key`     | Flow field used for the lookup                                   |
| `fields`  | Field mappings in `source:output` format, separated by `;`       |
| `reload`  | Optional automatic reload interval, such as `10s`, `1m`, or `1h` |

Supported lookup keys:

- `src_addr`
- `dst_addr`
- `next_hop`
- `sampler_address`

## CSV

CSV enrichment files must contain a `prefix`, `cidr`, or `network` column, plus any fields
you want to use for enrichment. The prefix column is found by name, so it can appear in any
position.

Lookups are longest-prefix matches, so a more specific row wins over one that covers it.

For example:

```csv
prefix,asn,org
1.0.0.0/24,13335,CLOUDFLARENET
1.0.16.0/24,2519,VECTANT ARTERIA Networks Corporation
```

Map CSV columns to output fields using `fields`:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=asn:dst_asn;org:dst_org"
```

In this example:

```text
asn -> dst_asn
org -> dst_org
```

The prefix column can be mapped like any other, which makes the collector emit the network
that actually matched:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=prefix:dst_network;asn:dst_asn"
```

With the table above, `1.0.0.1` gets a `dst_network` of `1.0.0.0/24`.

## MaxMind DB

MaxMind DB files can also be used as enrichment sources.

The source format is detected from the `.mmdb` extension.

Use dotted paths to access nested fields:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=GeoLite2-City.mmdb,key=src_addr,fields=country.iso_code:src_country;city.names.en:src_city"
```

Examples of MMDB field paths include:

```text
country.iso_code
city.names.en
location.latitude
location.longitude
```

## Multiple Enrichments

`--enrich` can be specified multiple times.

For example, destination addresses can be enriched from both an ASN database and a GeoIP database:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=asn:dst_asn;org:dst_org" \
  --enrich "type=prefix_lookup,source=GeoLite2-Country.mmdb,key=dst_addr,fields=country.iso_code:dst_country"
```

## Automatic Reload

Use `reload` to periodically reload an enrichment source without restarting the collector.

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=asn.csv,key=dst_addr,fields=asn:dst_asn,reload=30s"
```

Another example using a MaxMind database:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=GeoLite2-Country.mmdb,key=dst_addr,fields=country.iso_code:dst_country,reload=1h"
```
