# Library

The collector is built on `rustflow_core_new`, which parses NetFlow v5, NetFlow v9, IPFIX and sFlow v5, converts what they carry into records of IPFIX information elements, reads datagrams from sockets and captures, and writes records out again as packets. The crate is in the repository under `crates/rustflow_core_new` and is not published yet; it replaces the earlier `rustflow_lib` and `rustflow_core` crates, which are no longer maintained.

The crate's own [README](../crates/rustflow_core_new/README.md) describes its structure, the specifications it implements and every API in detail. What follows is the short version.

## Reading flows

A `Reader` is bound to a socket for one family: `Family::Netflow` reads NetFlow v5, NetFlow v9 and IPFIX, told apart by the version at the start of each datagram; `Family::Sflow` reads sFlow v5.

```rust
use rustflow_core_new::reader::{Family, Reader};

let reader = Reader::bind("0.0.0.0:9995", Family::Netflow)?;
for record in reader.flows() {
    println!("{:?}", record?);
}
```

`flows()` yields flow records only. `read()` gives every outcome, options records, timeouts and malformed datagrams among them. A capture file is read the same way through `PcapReader`, and with the `tokio` feature `AsyncReader` has the same shape, awaited.

## Common flows

`CommonFlow` is the fixed schema the collector writes out, made from any record:

```rust
use rustflow_core_new::convert::CommonFlow;

for record in reader.flows() {
    let flow = CommonFlow::from(&record?);
    println!("{:?} -> {:?}: {:?} bytes", flow.src_addr, flow.dst_addr, flow.bytes);
}
```

## Configuring the collector

The readers drive a `Collector`, which is where the information element registry, the template timeout, the holding of data that arrives before its template, and how exporters are told apart are set:

```rust
use std::net::UdpSocket;
use std::time::Duration;

use rustflow_core_new::protocol::information_element::Registry;
use rustflow_core_new::reader::{Collector, Family, Reader, SessionKey};

let collector = Collector::new(Family::Netflow, Registry::iana(), Duration::from_secs(1800))
    .with_session_key(SessionKey::Transport);
let reader = Reader::new(UdpSocket::bind("0.0.0.0:9995")?, collector);
```

By default an exporter is one session whatever source port its datagrams come from, as some routers send templates and data from different ports.

## Custom information elements

Elements go into the registry before the collector is built, which is the same mechanism behind the collector's `--ie-mapping` flag:

```rust
use std::borrow::Cow;

use rustflow_core_new::protocol::information_element::{
    DataType, ElementId, InformationElement, Registry,
};

let mut registry = Registry::iana();
registry.insert(InformationElement {
    id: ElementId::from((9, 1)),
    name: Cow::Borrowed("ciscoExample"),
    data_type: DataType::Unsigned32,
    semantics: None,
});
```

## Exporting

The `export` module is the reverse of reading: records go in, packets of a protocol come out, with templates and sequence numbers kept by the exporter. The `rustflow export` and `rustflow generate` commands are built on it.

```rust
use std::time::{Duration, SystemTime};

use rustflow_core_new::export::ipfix::Exporter;
use rustflow_core_new::protocol::ipfix;

let mut exporter = Exporter::new(1).with_template_refresh(Duration::from_secs(30));
let packet = exporter.export(&records, SystemTime::now())?;
let mut buf = Vec::new();
ipfix::write(&packet, &mut buf)?;
socket.send_to(&buf, collector)?;
```

## Packets

The protocol types are under `rustflow_core_new::protocol`: `ipfix`, `netflow_v5`, `netflow_v9` and `sflow_v5`, each with its packet structs, a parser and a `write`. With the `serde` feature a packet serializes as it is, or as text with its records named through `Packet::text(&registry)`, which is what the collector's raw output is.
