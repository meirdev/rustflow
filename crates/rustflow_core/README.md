# rustflow_core

NetFlow v5, NetFlow v9, IPFIX and sFlow v5, from datagrams to records of
IPFIX information elements. The crate parses and writes the packets of each
protocol, converts what they carry into one record shape, and reads
datagrams from a socket or a capture to give back those records.

It is the Collecting Process and the Conversion Process of an IPFIX
Mediator (RFC 6183 sections 5.1 and 5.3.2.1): whatever an exporter speaks,
what comes out is records of IPFIX information elements, options records
included.

## Structure

```
src/
├── protocol/    packets of each protocol, parsed and written back
│   ├── netflow_v5/
│   ├── netflow_v9/
│   ├── ipfix/
│   ├── sflow_v5/
│   ├── information_element/   element ids, the IANA registry, type records
│   └── value/                 values of the IANA data types, encoded and decoded
├── dissect/     captured packets read through link layers and tunnels
├── convert/     parsed packets to records of information elements
├── reader/      datagrams from a socket or a capture to records
├── export/      records to packets of a protocol, templates and sequence numbers kept
├── text/        records and packets as RFC 7373 text, for JSON (feature `serde`)
└── bytes/       big-endian reading and writing (private)
```

- `protocol` turns a datagram into a `Packet` and a `Packet` back into
  bytes. NetFlow v9 and IPFIX need templates between datagrams, so each has
  a `Parser` that keeps them, scoped by observation domain and expiring
  after a timeout. NetFlow v5 and sFlow v5 have a plain `parse` function.
  Every protocol has a `write`.
- `dissect` reads the packet headers that sFlow samples and that IPFIX
  carries in packet sections: Ethernet, VLAN tags, Linux cooked captures,
  MPLS, GRE, ERSPAN, VXLAN and Geneve, down to IP and transport headers.
- `convert` turns a parsed packet into `Record`s. A record is its
  protocol, the packet's sequence number, a scope for an options record,
  the list of elements and the values in that order. Conversion adds what a
  later stage needs without the packet: absolute times, the exporter and
  when the datagram was received, and the sampling the exporter stated in
  its options.
- `reader` receives datagrams and gives back records: `Reader` from a
  socket, `AsyncReader` with tokio, `PcapReader` from a capture. All three
  drive a `Collector`, which keeps a session per exporter transport address
  with the templates and options of each protocol it speaks.
- `export` is the reverse of `convert`: an exporter for each protocol
  turns records into its packets, making templates from the records'
  elements and keeping the sequence numbers, so that a collector reads back
  what went in. For a traffic generator, or a mediator's exporting side.

## Specifications implemented

| Specification | What |
|---|---|
| Cisco NetFlow v5 | Fixed-format flow records |
| RFC 3954 | NetFlow v9: templates, options templates, scopes, FlowSet padding |
| RFC 7011 | IPFIX: message format, templates, options, variable-length fields, transport sessions; withdrawals parsed, not applied |
| RFC 6313 | IPFIX structured data: basicList, subTemplateList, subTemplateMultiList |
| RFC 5610 | IPFIX type records: elements an exporter describes in options data |
| RFC 7013 | Information element specifiers, used for naming unregistered elements |
| RFC 5477 | PSAMP packet sections: sampled headers dissected into flow fields |
| RFC 7373 | Textual representation of elements and values, for JSON output |
| RFC 6183 | IPFIX Mediation: the Collecting and Conversion Processes, scoped sessions, added elements |
| RFC 7119 | Mediation at an upstream mediator: original exporter and collection time kept, not overwritten |
| sFlow version 5 | Datagrams, flow samples with sampled headers, counter samples |
| RFC 2784, RFC 7348, RFC 8926 | GRE, VXLAN and Geneve tunnels in dissected packets |

The IANA information element registry is built in, with the data types and
semantics of every element.

## Reading records

A `Reader` is bound to a socket for one family: `Family::Netflow` reads
NetFlow v5, NetFlow v9 and IPFIX, told apart by the version at the start
of each datagram; `Family::Sflow` reads sFlow v5. A reader is an iterator
of records.

```rust
use rustflow_core::reader::{Family, Reader};

let reader = Reader::bind("0.0.0.0:9995", Family::Netflow)?;
for record in reader.flows() {
    println!("{:?}", record?);
}
```

`flows()` yields flow records only. Reading through `read()` gives every
outcome, options records among them:

```rust
use std::time::Duration;

use rustflow_core::reader::{Family, Read, Reader};

let mut reader = Reader::bind("0.0.0.0:9995", Family::Netflow)?
    .with_read_timeout(Some(Duration::from_secs(5)))?;
loop {
    match reader.read()? {
        Read::Record(record) if record.is_options() => {
            println!("options for {:?}: {:?}", record.scope, record);
        }
        Read::Record(flow) => println!("{flow:?}"),
        Read::Timeout => break,
        Read::Malformed { exporter, error } => eprintln!("{exporter}: {error}"),
    }
}
```

Options records are records with a non-empty `scope`: what they describe,
such as an observation domain or an interface. The collector keeps the
latest of each kind and applies what they say, sampling rates in
particular, to the flows that follow. The latest ones are also there to
look up:

```rust
use rustflow_core::protocol::information_element::iana;

for (exporter, record) in reader.options().by_element(iana::INTERFACE_NAME) {
    println!("{exporter}: {:?}", record.first(iana::INTERFACE_NAME));
}
```

### Configuring the collector

The readers take a `Collector`, which is where the information element
registry, the template timeout and the holding of early data are set. The
socket's own settings stay on the reader.

```rust
use std::net::UdpSocket;
use std::time::Duration;

use rustflow_core::protocol::information_element::Registry;
use rustflow_core::reader::{Collector, Family, PendingLimits, Reader};

let registry = Registry::iana();
let collector = Collector::new(Family::Netflow, registry, Duration::from_secs(1800))
    .with_pending(PendingLimits::new(1 << 20, Duration::from_secs(60)));
let reader = Reader::new(UdpSocket::bind("0.0.0.0:9995")?, collector)
    .with_recv_buffer_size(8 << 20)?;
```

`with_pending` holds NetFlow v9 and IPFIX data sets that arrive before
their template, within the limits given per protocol of a session, and
converts them when the template comes. Without it, such data is read past.
`with_recv_buffer_size` needs the `socket2` feature.

Sessions are told apart by the exporter's IP address, so an exporter that
sends templates and data from different source ports is one session.
`with_session_key(SessionKey::Transport)` keys them by address and port,
the transport session of RFC 7011, for collectors behind which two
exporting processes share a host.

Custom elements go into the registry before the collector is built:

```rust
use rustflow_core::protocol::information_element::{
    DataType, ElementId, InformationElement, Registry,
};

let mut registry = Registry::iana();
registry.insert(InformationElement::new(
    ElementId::from((9, 1)),
    "ciscoExample",
    DataType::Unsigned32,
));
```

### Async and captures

With the `tokio` feature, `AsyncReader` has the same shape, awaited, and
is a `Stream` of records:

```rust
use rustflow_core::reader::{AsyncReader, Family};

let mut reader = AsyncReader::bind("0.0.0.0:9995", Family::Netflow).await?;
loop {
    let flow = reader.next_flow().await?;
    println!("{flow:?}");
}
```

With the `pcap` feature, `PcapReader` reads the UDP datagrams of a
capture, whatever link layer it was taken on, as a socket reader would
have received them. Each record's receive time is the capture time.

```rust
use rustflow_core::reader::{Family, PcapReader};

let reader = PcapReader::open("exporters.pcap", Family::Netflow)?;
for record in reader.flows() {
    println!("{:?}", record?);
}
```

## Records

A `Record` holds its values and the elements that say what each one is.
Records of one shape, such as those of one template, share their element
list, and a value is found by element without a scan.

```rust
use rustflow_core::protocol::information_element::iana;
use rustflow_core::protocol::value::Value;

if let Some(Value::Unsigned64(octets)) = record.first(iana::OCTET_DELTA_COUNT) {
    println!("{octets} octets");
}
for (element, value) in record.iter() {
    println!("{element}: {value}");
}
```

Every converted record carries, besides what the exporter sent:

- `originalExporterIPv4Address` or `originalExporterIPv6Address` and
  `exporterTransportPort`, the exporter's transport address, unless an
  upstream mediator already named the original exporter;
- `originalObservationDomainID` for protocols that have a domain;
- `collectionTimeMilliseconds`, when the datagram was received;
- absolute `flowStartMilliseconds` and `flowEndMilliseconds` in place of
  the uptime-relative times NetFlow v5 and v9 export;
- the sampling the exporter stated, as the PSAMP selector elements
  `selectorAlgorithm`, `samplingSize` and `samplingPopulation`, from
  NetFlow v5's header, sFlow's samples, or the options records that apply
  to the flow's sampler, interface or domain.

## Converting to a common flow

`CommonFlow` is a fixed set of fields for consumers that want those rather
than elements: addresses, ports, protocol, counters, times, interfaces, AS
numbers, VLANs, MAC addresses and the sampling rate. It is a view of a
record, one mapping whatever protocol the record arrived in.

```rust
use rustflow_core::convert::CommonFlow;

for record in reader.flows() {
    let flow = CommonFlow::from(&record?);
    println!("{:?} -> {:?}: {:?} bytes", flow.src_addr, flow.dst_addr, flow.bytes);
}
```

Where a field has several elements it can come from, such as
`octetDeltaCount` or `layer2OctetDeltaCount` for `bytes`, the first the
record has gives it. A `Mapper` does the same for a stream of records,
working out once per element list where each field comes from, which is
how the collector converts:

```rust
use rustflow_core::convert::Mapper;

let mut mapper = Mapper::default();
for record in reader.flows() {
    let flow = mapper.flow(&record?);
}
```

With the `serde` feature, `CommonFlow` serializes with its field names,
unset fields left out.

## Converting to IPFIX text

With the `serde` feature, a record serializes as a map from element names
to values in their RFC 7373 textual representation, which is what an IPFIX
record looks like in JSON. The registry gives the names.

```rust
use rustflow_core::protocol::information_element::Registry;

let registry = Registry::iana();
for record in reader.flows() {
    println!("{}", serde_json::to_string(&record?.text(&registry))?);
}
```

An element the registry does not know is named by its specifier, `(id)`
or `(pen/id)`. An element a record holds more than once comes out as an
array.

## Parsing and writing packets

The converters and readers are built on parsers that can be used alone.
NetFlow v9 and IPFIX parsers keep templates between calls:

```rust
use std::time::Duration;

use rustflow_core::protocol::information_element::Registry;
use rustflow_core::protocol::ipfix::{self, Set};

let mut parser = ipfix::Parser::new(Registry::iana(), Duration::from_secs(600));
let packet = parser.parse(&datagram)?;
for set in &packet.sets {
    if let Set::Data(data) = set {
        println!("template {}: {} records", data.template.template_id, data.records.len());
    }
}

let mut buf = Vec::new();
ipfix::write(&packet, &mut buf)?;
```

A data set whose template has not been seen is kept as `Set::Undecoded`,
with its bytes, and written back as sent. Parsing is lax: a malformed set
ends the packet at that point, and the sets before it are kept.

A packet of any protocol can be converted without a reader, by giving the
converter where it came from:

```rust
use rustflow_core::convert::{Received, ipfix};
use rustflow_core::convert::Record;

let mut converter = ipfix::Converter::default();
let mut records: Vec<Record> = Vec::new();
converter.convert(packet, &Received { exporter, time: None }, &mut records);
```

## Exporting records

An `Exporter` is the reverse of a reader: records go in, packets of one
protocol come out. Records whose values take the same fields share a
template, with each field as wide as its value's type and strings
variable-length; records of a list carry their own templates along. A
message carries the templates before the first data of a new shape, and
again after the refresh interval.

```rust
use std::time::{Duration, SystemTime};

use rustflow_core::export::ipfix::Exporter;
use rustflow_core::protocol::ipfix;

let mut exporter = Exporter::new(1).with_template_refresh(Duration::from_secs(30));
let packet = exporter.export(&records, SystemTime::now())?;
let mut buf = Vec::new();
ipfix::write(&packet, &mut buf)?;
socket.send_to(&buf, collector)?;
```

A record with a scope goes out as an options record. The caller chooses how
many records go in a message.

Each protocol has one: `netflow_v9::Exporter` works as the IPFIX one with
flow times sent as uptimes, `netflow_v5::Exporter` fills the fixed format
from the elements it has fields for, and `sflow_v5::Exporter` sends each record
as a flow sample of one packet, its header built from the record's
addresses, ports and protocol. Those that count from boot take when the
exporter booted.

## Features

| Feature | Adds |
|---|---|
| `serde` | `Serialize` for packets, values, records as RFC 7373 text, and `CommonFlow` |
| `tokio` | `AsyncReader` |
| `pcap` | `PcapReader` |
| `socket2` | Receive buffer sizing on the socket readers; implied by `tokio` |
| `jiff` | `Value::timestamp`, a timestamp value as a `jiff::Timestamp` |

With no features, the crate depends on `etherparse`, `macaddr`,
`num_enum` and `rustc-hash` only.
