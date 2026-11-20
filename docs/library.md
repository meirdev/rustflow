# Library

The parsing, conversion and readers used by `rustflow collect` are published as the
`rustflow_core` crate, so NetFlow, IPFIX, and sFlow can be decoded inside your own
application.

```toml
[dependencies]
rustflow_core = "0.21"
```

Heavier dependencies are behind features: `pcap` for reading capture files, `tokio` for
the async reader, and `serde` for serializing packets and flows.

## Reading Flows From the Network

`NetflowReader` and `SflowReader` bind a UDP socket. `flows` turns a reader into an
iterator of normalized [common flows](output.md#common-flow):

```rust
use rustflow_core::reader::NetflowReader;

fn main() -> std::io::Result<()> {
    for flow in NetflowReader::bind("0.0.0.0:9995")?.flows() {
        let flow = flow?;
        println!("{:?} -> {:?} {:?} bytes", flow.src_addr, flow.dst_addr, flow.bytes);
    }

    Ok(())
}
```

`NetflowReader` handles NetFlow v5, NetFlow v9, and IPFIX on the same socket; the version
is detected per datagram. `SflowReader` handles sFlow v5.

A datagram usually carries many flows, which are buffered and returned one by one.

> A socket reader never finishes. When no data arrives it keeps waiting, so the loop only
> ends if you `break` out of it or a socket error occurs.

### Reading Without an Iterator

`read` gives you control over the waiting. It returns a `Read`: `Item` with the next flow,
`Timeout` when none arrived before the read timeout, or `Malformed` for a datagram that
could not be decoded, with its sender and the error. It returns `None` only at the end of
the input, which a socket never reaches:

```rust
use std::time::Duration;

use rustflow_core::reader::{NetflowReader, Read};

fn main() -> std::io::Result<()> {
    let mut reader =
        NetflowReader::bind("0.0.0.0:9995")?.with_read_timeout(Some(Duration::from_secs(1)))?;

    while let Some(read) = reader.read()? {
        match read {
            Read::Item(flow) => println!("{flow:?}"),
            Read::Malformed { from, error } => eprintln!("undecodable datagram from {from}: {error}"),
            Read::Timeout => {
                // No flow within the timeout: flush metrics, check for
                // shutdown, then keep reading.
            }
        }
    }

    Ok(())
}
```

Without `with_read_timeout`, `read` blocks until a datagram arrives. A `StopHandle`, from
`stop_handle`, ends a reader from another thread.

### Reading One Datagram at a Time

`read` and `flows` give the flows one by one and drop the datagram they came in.
`read_datagram` keeps it: a `Batch` with the sender, the receive time, the payload length,
the flows, and a `Summary` of what the datagram held. This is the call to build metrics on:

```rust
use rustflow_core::reader::{NetflowReader, Read};

fn main() -> std::io::Result<()> {
    let mut reader = NetflowReader::bind("0.0.0.0:9995")?;

    while let Some(read) = reader.read_datagram()? {
        match read {
            Read::Item(batch) => {
                let summary = batch.summary;
                println!(
                    "{} octets of {} from {}: {} flows, {} undecoded sets",
                    batch.length,
                    summary.flow_type.name(),
                    batch.from,
                    batch.flows.len(),
                    summary.undecoded_sets,
                );
            }
            Read::Malformed { from, error } => eprintln!("undecodable datagram from {from}: {error}"),
            Read::Timeout => {}
        }
    }

    Ok(())
}
```

`undecoded_sets` counts the data sets that were dropped because the exporter's template
for them is not known yet, or does not match them. A count that keeps rising for an
exporter means its templates are not arriving.

## Reading From a PCAP File

With the `pcap` feature, `NetflowPcapReader` and `SflowPcapReader` read the UDP datagrams
of a pcap or pcapng capture, received at their capture time. Unlike the socket readers they
finish at the end of the file:

```rust
use rustflow_core::reader::NetflowPcapReader;

fn main() -> std::io::Result<()> {
    let mut total = 0;
    for flow in NetflowPcapReader::open("capture.pcap")?.flows() {
        total += flow?.bytes.unwrap_or(0);
    }
    println!("{total} bytes across all flows");

    Ok(())
}
```

Templates expire by the capture's clock rather than by how fast the file is read.

## Async

With the `tokio` feature, `AsyncNetflowReader` and `AsyncSflowReader` await the datagrams
of a socket instead of blocking on them:

```toml
[dependencies]
rustflow_core = { version = "0.21", features = ["tokio"] }
tokio = { version = "1", features = ["full"] }
```

Their `read` waits for the next datagram, so wrap it in `tokio::time::timeout` to stop
waiting; they are also `Stream`s:

```rust
use rustflow_core::reader::{AsyncNetflowReader, Read};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut reader = AsyncNetflowReader::bind("0.0.0.0:9995").await?;

    loop {
        if let Read::Item(flow) = reader.read().await? {
            println!("{flow:?}");
        }
    }
}
```

## Custom Information Elements

Enterprise-specific IPFIX Information Elements go into a `Registry` before the processor is
built, which is the same mechanism behind the collector's `--ie-mapping` flag:

```rust
use std::borrow::Cow;

use rustflow_core::information_element::{DataType, ElementId, InformationElement, Registry};
use rustflow_core::reader::{NetflowProcessor, NetflowReader, Reader, UdpSource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = Registry::iana();
    registry.insert(InformationElement {
        id: ElementId::new(Some(9), 1)?,
        name: Cow::Borrowed("ciscoExample"),
        data_type: DataType::Unsigned32,
        semantic: None,
        unit: None,
        range: None,
        description: None,
    })?;

    let reader: NetflowReader =
        Reader::new(UdpSource::bind("0.0.0.0:4739")?, NetflowProcessor::new(registry));
    for flow in reader.flows() {
        println!("{:?}", flow?);
    }

    Ok(())
}
```

`Registry::iana` starts from IANA's registry; `Registry::empty` starts empty.

## Template Cache

NetFlow v9 and IPFIX send templates separately from data, and data records cannot be
decoded until their template arrives. Cached templates expire after 30 minutes by default:

```rust
use std::time::Duration;

use rustflow_core::information_element::Registry;
use rustflow_core::reader::{NetflowProcessor, NetflowReader, Reader, UdpSource};

fn main() -> std::io::Result<()> {
    let processor = NetflowProcessor::new(Registry::iana()).with_template_ttl(Duration::from_secs(600));
    let reader: NetflowReader = Reader::new(UdpSource::bind("0.0.0.0:9995")?, processor);

    for flow in reader.flows() {
        println!("{:?}", flow?);
    }

    Ok(())
}
```

## Raw Protocol Access

`flows` normalizes into the common schema. To work with the packets as they are, with their
templates, per-field values and options records, use `packets` (or `read_raw`, which also
reports timeouts and malformed datagrams):

```rust
use rustflow_core::reader::{NetflowPacket, NetflowReader};

fn main() -> std::io::Result<()> {
    for raw in NetflowReader::bind("0.0.0.0:9995")?.packets() {
        let raw = raw?;
        match raw.packet {
            NetflowPacket::V5(packet) => {
                println!("v5 from {}: {} records", raw.from, packet.flow_records.len())
            }
            NetflowPacket::V9(packet) => {
                println!("v9 from {}: {} flow sets", raw.from, packet.flow_sets.len())
            }
            NetflowPacket::Ipfix(packet) => {
                println!("ipfix from {}: {} sets", raw.from, packet.sets.len())
            }
        }
    }

    Ok(())
}
```

`SflowPacket::V5` is the sFlow counterpart. The protocol types are in
`rustflow_core::ipfix`, `rustflow_core::netflow_v5`, `rustflow_core::netflow_v9`, and
`rustflow_core::sflow_v5`, each with its parser and encoder. With the `serde` feature a
packet serializes as it is, which is what the collector's raw output is.

## Bringing Your Own Transport

If the datagrams reach you some other way, such as a message queue or a capture library,
use a processor directly. This is what the readers are built on:

```rust
use std::net::IpAddr;
use std::time::Instant;

use jiff::Timestamp;
use rustflow_core::common_flow::CommonFlow;
use rustflow_core::reader::{NetflowProcessor, Processor};

fn decode(exporter: IpAddr, payload: &[u8], processor: &mut NetflowProcessor) {
    let mut flows: Vec<CommonFlow> = Vec::new();
    match processor.process(exporter, payload, Timestamp::now(), Instant::now(), &mut flows) {
        Ok(summary) => {
            println!("{}: {} flows", summary.flow_type.name(), summary.flows);
            for flow in flows {
                println!("{flow:?}");
            }
        }
        Err(error) => eprintln!("undecodable datagram from {exporter}: {error}"),
    }
}

fn main() {
    let mut processor = NetflowProcessor::default();
    decode([192, 0, 2, 1].into(), &[/* a UDP payload */], &mut processor);
}
```

The processor is stateful: it holds the templates and options of each exporter, keyed by
its address, so keep one per collector rather than creating one per datagram. The
`Timestamp` is the receive time the flows are stamped with, and the `Instant` is the clock
templates expire by. `process` is `parse` followed by `convert`; call those two yourself
when you also want the packet as it is.

`SflowProcessor` is the sFlow equivalent.

## Flow Fields

`CommonFlow` is in `rustflow_core::common_flow`. Every field and its type is listed in
[Output](output.md#common-flow). Optional fields are `Option<T>` and are `None` when the
exporter did not supply them, so prefer matching over unwrapping:

```rust
use rustflow_core::common_flow::CommonFlow;

fn describe(flow: &CommonFlow) -> String {
    match (flow.src_addr, flow.dst_addr) {
        (Some(src), Some(dst)) => format!("{src} -> {dst}"),
        _ => "no addresses in this record".to_string(),
    }
}
```
