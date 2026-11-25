# Fuzzing

Fuzz targets for `rustflow_core`, run with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and a nightly toolchain:

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Targets

| Target              | Input                                                    | What it runs                                                         |
| ------------------- | -------------------------------------------------------- | -------------------------------------------------------------------- |
| `netflow`           | Datagrams of one exporter, each after a two-octet length | NetFlow v5, v9 and IPFIX: parse, convert to flows, serialize, encode |
| `sflow`             | One datagram                                             | sFlow v5: parse, convert to flows, serialize, encode                 |
| `pcap`              | A pcap or pcapng file                                    | The capture reader, then every UDP datagram as NetFlow and as sFlow  |
| `roundtrip_netflow` | As `netflow`                                             | Parse, encode, parse again: the same packet and the same octets      |
| `roundtrip_sflow`   | As `sflow`                                               | Parse, encode, parse again: the same packet and the same octets      |

The `netflow` input holds several datagrams so that a template can come before the data that
needs it.

The round-trip targets compare a packet with what it parses to after being written. An IPFIX
message's length is left out of that, since the encoder pads each set to four octets and a
message as sent may not.

## Running

From the repository root:

```sh
make fuzz-corpus              # seed the corpus from the captures under tests/fixtures
make fuzz TARGET=netflow      # until stopped, or until it finds a failure
make fuzz TARGET=sflow FUZZ_ARGS=-max_total_time=300
```

A failing input is saved under `fuzz/artifacts/<target>/`. To run it again:

```sh
cargo +nightly fuzz run netflow fuzz/artifacts/netflow/crash-<hash>
```

The fuzz build has overflow checks on, so it also finds arithmetic that would wrap silently in a
release build. When a failure is fixed, add a unit test for it next to the fix; the corpus and
the artifacts are not committed.
