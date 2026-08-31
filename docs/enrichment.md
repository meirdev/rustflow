# Enrichment

RustFlow can enrich normalized flows using prefix lookups from CSV or MaxMind DB (`.mmdb`) files.

Enrichment is configured with `--enrich` and can be specified multiple times.

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=asn.csv,prefix_column=prefix,fields=dst_addr@asn:dst_asn"
```

## Parameters

| Parameter       | Description                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------- |
| `type`          | Lookup type. Currently `prefix_lookup`                                                      |
| `source`        | Path to a CSV or MaxMind DB (`.mmdb`) file                                                  |
| `fields`        | Lookup groups in `<key>@<source>:<output>[\|<source>:<output>...]` format, separated by `;` |
| `prefix_column` | Name of the column holding the prefix. Required for CSV sources                             |
| `reload`        | Optional automatic reload: an interval such as `10s`, `1m`, or `1h`                         |

### Fields

Each `fields` group starts with the flow field whose address is looked up (the key),
followed by `@` and one or more `source:output` mappings separated by `|`. Groups are
separated by `;`, so a single source can be looked up with several keys:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=GeoLite2-City.mmdb,fields=src_addr@country.iso_code:src_country|city.names.en:src_city;dst_addr@country.iso_code:dst_country|city.names.en:dst_city"
```

In this example:

```text
src_addr -> country.iso_code -> src_country
src_addr -> city.names.en    -> src_city
dst_addr -> country.iso_code -> dst_country
dst_addr -> city.names.en    -> dst_city
```

Supported keys:

- `src_addr`
- `dst_addr`
- `next_hop`
- `sampler_address`

## CSV

CSV enrichment files must contain a prefix column, plus any fields you want to use for
enrichment. Name the prefix column with `prefix_column`; it is found by name, so it can
appear in any position.

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
  --enrich "type=prefix_lookup,source=asn.csv,prefix_column=prefix,fields=dst_addr@asn:dst_asn|org:dst_org"
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
  --enrich "type=prefix_lookup,source=asn.csv,prefix_column=prefix,fields=dst_addr@prefix:dst_network|asn:dst_asn"
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
  --enrich "type=prefix_lookup,source=GeoLite2-City.mmdb,fields=src_addr@country.iso_code:src_country|city.names.en:src_city"
```

Values are converted to strings regardless of their type in the database, so
numeric fields such as `autonomous_system_number` in GeoLite2-ASN work as well:

```bash
rustflow collect \
  -t netflow \
  -p 9995 \
  -f common \
  --enrich "type=prefix_lookup,source=GeoLite2-ASN.mmdb,fields=src_addr@autonomous_system_number:src_asn|autonomous_system_organization:src_as_org"
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
  --enrich "type=prefix_lookup,source=asn.csv,prefix_column=prefix,fields=dst_addr@asn:dst_asn|org:dst_org" \
  --enrich "type=prefix_lookup,source=GeoLite2-Country.mmdb,fields=dst_addr@country.iso_code:dst_country"
```
