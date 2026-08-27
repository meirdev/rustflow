# Library

The parsing and normalization used by `rustflow collect` is published as a library, so
NetFlow, IPFIX, and sFlow can be decoded inside your own application.

The crate is named `rustflow_lib` because `rustflow` was already taken on crates.io.

```toml
[dependencies]
rustflow_lib = "0.11"
```

## Reading Flows From the Network

`NetflowReader` and `SflowReader` bind a UDP socket and yield normalized
[common flows](output.md#common-flow). Both implement `Iterator`, so a collector is a
`for` loop:

```rust
use rustflow_lib::NetflowReader;

fn main() -> std::io::Result<()> {
    let reader = NetflowReader::bind("0.0.0.0:9995")?;

    for flow in reader {
        let flow = flow?;
        println!("{} -> {} {} bytes",
            flow.src_addr.unwrap(), flow.dst_addr.unwrap(), flow.bytes);
    }

    Ok(())
}
```

`NetflowReader` handles NetFlow v5, NetFlow v9, and IPFIX on the same socket; the version
is detected per packet. `SflowReader` handles sFlow v5:

```rust
use rustflow_lib::SflowReader;

fn main() -> std::io::Result<()> {
    let reader = SflowReader::bind("0.0.0.0:6343")?;

    for flow in reader {
        println!("{:?}", flow?);
    }

    Ok(())
}
```

One flow record is yielded at a time. A single UDP packet usually carries many records,
which are buffered internally and returned one by one.

> The socket iterators never finish. When no data arrives they keep waiting, so the loop
> only ends if you `break` out of it or a socket error occurs.

### Reading Without an Iterator

`read` gives you control over the waiting. It returns `Ok(None)` when no datagram arrived
before the read timeout, which is the hook for doing other work in the same thread:

```rust
use rustflow_lib::NetflowReader;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let mut reader = NetflowReader::bind("0.0.0.0:9995")?
        .with_read_timeout(Some(Duration::from_secs(1)))?;

    loop {
        match reader.read()? {
            Some(flow) => println!("{:?}", flow),
            None => {
                // No flow within the timeout: flush metrics, check for
                // shutdown, then keep reading.
            }
        }
    }
}
```

Without `with_read_timeout`, `read` blocks until a packet arrives.

## Reading From a PCAP File

The pcap readers take the same shape, and unlike the socket readers they **do** finish, at
the end of the file:

```rust
use rustflow_lib::pcap::NetflowPcapReader;

fn main() -> std::io::Result<()> {
    let reader = NetflowPcapReader::open("capture.pcap")?;

    let mut total = 0u64;
    for flow in reader {
        total += flow?.bytes;
    }
    println!("{} bytes across all flows", total);

    Ok(())
}
```

`SflowPcapReader` is the sFlow equivalent. Both expect a pcap containing the UDP datagrams
carrying the flow protocol.

## Async

The async readers are behind the `tokio` feature:

```toml
[dependencies]
rustflow_lib = { version = "0.11", features = ["tokio"] }
tokio = { version = "1", features = ["full"] }
```

They live in `rustflow_lib::tokio` and mirror the sync API, except that `read` waits for a
flow rather than returning `Option`:

```rust
use rustflow_lib::tokio::NetflowReader;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut reader = NetflowReader::bind("0.0.0.0:9995").await?;

    loop {
        let flow = reader.read().await?;
        println!("{:?}", flow);
    }
}
```

## Custom Information Elements

Enterprise-specific IPFIX Information Elements are registered through an `IERegistry`,
which is the same mechanism behind the collector's `--ie-mapping` flag:

```rust
use rustflow_lib::{IERegistry, NetflowReader};

fn main() -> std::io::Result<()> {
    let mut registry = IERegistry::new_with_iana_elements();
    registry.load_from_csv("ie-mapping.csv").expect("failed to load IE mappings");

    let reader = NetflowReader::bind("0.0.0.0:4739")?
        .with_ie_registry(registry);

    for flow in reader {
        println!("{:?}", flow?);
    }

    Ok(())
}
```

`IERegistry::new_with_iana_elements` starts from the IANA registry;
`IERegistry::new` starts empty.

## Template Cache

NetFlow v9 and IPFIX send templates separately from data, and data records cannot be
decoded until their template arrives. Cached templates expire after 10 minutes by default:

```rust
use rustflow_lib::NetflowReader;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let reader = NetflowReader::bind("0.0.0.0:9995")?
        .with_template_timeout(Duration::from_secs(1800));

    for flow in reader {
        println!("{:?}", flow?);
    }

    Ok(())
}
```

Raise this if your exporters re-send templates infrequently.

## Raw Protocol Access

`read` normalizes into the common schema. To work with the protocol structures themselves —
template definitions, per-field values, options records — use `read_raw`:

```rust
use rustflow_lib::{NetflowPacket, NetflowReadResult, NetflowReader};

fn main() -> std::io::Result<()> {
    let mut reader = NetflowReader::bind("0.0.0.0:9995")?;

    loop {
        match reader.read_raw()? {
            NetflowReadResult::Packet { src, len, packet } => match packet {
                NetflowPacket::V5(p) => println!("v5 from {} ({} bytes): {} records",
                    src, len, p.flow_records.len()),
                NetflowPacket::V9(p) => println!("v9 from {}: {} flow sets",
                    src, p.flow_sets.len()),
                NetflowPacket::Ipfix(p) => println!("ipfix from {}: {} sets",
                    src, p.sets.len()),
            },
            NetflowReadResult::ParseError { src, version, .. } => {
                eprintln!("undecodable packet from {} (version {:?})", src, version);
            }
            NetflowReadResult::Timeout => {}
        }
    }
}
```

`SflowReadResult` is the sFlow counterpart, carrying `SflowPacket::V5`.

The protocol types are re-exported per protocol: `rustflow_lib::ipfix`,
`rustflow_lib::netflow_v5`, `rustflow_lib::netflow_v9`, and `rustflow_lib::sflow`.

## Bringing Your Own Transport

If the packets reach you some other way — a message queue, a capture library, a test
fixture — use a processor directly. This is what the readers are built on:

```rust
use rustflow_lib::NetflowProcessor;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

fn decode(exporter: IpAddr, payload: &[u8], processor: &mut NetflowProcessor) {
    // `time_received_ns` is what lands in the flow's `time_received_ns`
    // field; pass `None` to leave it unset.
    let received = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as i64);

    for flow in processor.process(exporter, payload, received) {
        println!("{:?}", flow);
    }
}

fn main() {
    let mut processor = NetflowProcessor::new();
    let exporter = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    decode(exporter, &[/* a UDP payload */], &mut processor);
}
```

The processor is stateful: it holds the template cache and the sampling-rate cache, so keep
one per collector rather than creating one per packet. Key it by exporter address, which is
what `process` uses to scope templates.

`SflowProcessor` is the sFlow equivalent; because sFlow carries no templates, its `process`
takes only the payload and the receive time.

## Flow Fields

`CommonFlow` is re-exported as `rustflow_lib::CommonFlow`. Every field and its type is
listed in [Output](output.md#common-flow). Optional fields are `Option<T>` and are `None`
when the exporter did not supply them, so prefer matching over unwrapping:

```rust
use rustflow_lib::CommonFlow;

fn describe(flow: &CommonFlow) -> String {
    match (flow.src_addr, flow.dst_addr) {
        (Some(src), Some(dst)) => format!("{} -> {}", src, dst),
        _ => "no addresses in this record".to_string(),
    }
}
```
