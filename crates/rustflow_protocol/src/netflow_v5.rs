//! NetFlow v5: a fixed 24-byte header followed by `count` fixed 48-byte flow
//! records.

use std::net::Ipv4Addr;

use rustflow_bytes::{Reader, Writer};

use crate::{ParseError, WriteError};

pub const VERSION: u16 = 5;

/// The low 14 bits of the sampling field.
const SAMPLING_INTERVAL_MASK: u16 = 0x3fff;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Packet {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub header: Header,
    pub flow_records: Vec<FlowRecord>,
}

/// The packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    /// NetFlow export format version number.
    pub version: u16,
    /// Number of flows exported in this packet.
    pub count: u16,
    /// Current time in milliseconds since the export device booted.
    pub sys_uptime: u32,
    /// Current count of seconds since 0000 UTC 1970.
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 UTC 1970.
    pub unix_nsecs: u32,
    /// Sequence counter of total flows seen.
    pub flow_sequence: u32,
    /// Type of flow-switching engine.
    pub engine_type: u8,
    /// Slot number of the flow-switching engine.
    pub engine_id: u8,
    /// Sampling mode and interval.
    pub sampling_interval: Sampling,
}

/// The header's 16-bit `sampling_interval` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Sampling {
    /// The first two bits.
    pub mode: u8,
    /// The remaining 14 bits: one of every `interval` packets is sampled.
    pub interval: u16,
}

impl From<u16> for Sampling {
    fn from(field: u16) -> Self {
        Self {
            mode: field.to_be_bytes()[0] >> 6,
            interval: field & SAMPLING_INTERVAL_MASK,
        }
    }
}

impl TryFrom<Sampling> for u16 {
    type Error = WriteError;

    fn try_from(sampling: Sampling) -> Result<Self, WriteError> {
        if sampling.mode > 3 {
            return Err(WriteError::TooLarge {
                field: "sampling mode",
                value: usize::from(sampling.mode),
            });
        }
        if sampling.interval > SAMPLING_INTERVAL_MASK {
            return Err(WriteError::TooLarge {
                field: "sampling interval",
                value: usize::from(sampling.interval),
            });
        }
        Ok((u16::from(sampling.mode) << 14) | sampling.interval)
    }
}

/// A flow record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowRecord {
    /// Source IP address.
    pub srcaddr: Ipv4Addr,
    /// Destination IP address.
    pub dstaddr: Ipv4Addr,
    /// IP address of the next hop router.
    pub nexthop: Ipv4Addr,
    /// SNMP index of the input interface.
    pub input: u16,
    /// SNMP index of the output interface.
    pub output: u16,
    /// Packets in the flow.
    pub d_pkts: u32,
    /// Total number of Layer 3 bytes in the packets of the flow.
    pub d_octets: u32,
    /// `sys_uptime` at the start of the flow.
    pub first: u32,
    /// `sys_uptime` when the last packet of the flow was received.
    pub last: u32,
    /// TCP/UDP source port number or equivalent.
    pub srcport: u16,
    /// TCP/UDP destination port number or equivalent.
    pub dstport: u16,
    /// Cumulative OR of TCP flags.
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6, UDP = 17).
    pub prot: u8,
    /// IP type of service (ToS).
    pub tos: u8,
    /// Autonomous system number of the source, either origin or peer.
    pub src_as: u16,
    /// Autonomous system number of the destination, either origin or peer.
    pub dst_as: u16,
    /// Source address prefix mask bits.
    pub src_mask: u8,
    /// Destination address prefix mask bits.
    pub dst_mask: u8,
}

/// Parses a NetFlow v5 datagram. Bytes after the last flow record are
/// ignored.
pub fn parse(datagram: &[u8]) -> Result<Packet, ParseError> {
    let mut r = Reader::new(datagram);
    let header = parse_header(&mut r)?;
    let flow_records = r.repeat(usize::from(header.count), parse_flow_record)?;

    Ok(Packet {
        header,
        flow_records,
    })
}

/// Writes `packet` as a NetFlow v5 datagram at the end of `buf`. The count
/// written is the number of flow records, whatever the header holds, and
/// padding is written as zeros. On error, nothing is written.
pub fn write(packet: &Packet, buf: &mut Vec<u8>) -> Result<(), WriteError> {
    let mut w = Writer::new(buf);
    write_header(&mut w, &packet.header, packet.flow_records.len())?;
    for record in &packet.flow_records {
        write_flow_record(&mut w, record);
    }
    Ok(())
}

fn parse_header(r: &mut Reader) -> Result<Header, ParseError> {
    let version = r.u16()?;
    if version != VERSION {
        return Err(ParseError::Version(version.into()));
    }
    let count = r.u16()?;
    let sys_uptime = r.u32()?;
    let unix_secs = r.u32()?;
    let unix_nsecs = r.u32()?;
    let flow_sequence = r.u32()?;
    let engine_type = r.u8()?;
    let engine_id = r.u8()?;
    let sampling_interval = Sampling::from(r.u16()?);

    Ok(Header {
        version,
        count,
        sys_uptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval,
    })
}

fn parse_flow_record(r: &mut Reader) -> Result<FlowRecord, ParseError> {
    let srcaddr = r.ipv4()?;
    let dstaddr = r.ipv4()?;
    let nexthop = r.ipv4()?;
    let input = r.u16()?;
    let output = r.u16()?;
    let d_pkts = r.u32()?;
    let d_octets = r.u32()?;
    let first = r.u32()?;
    let last = r.u32()?;
    let srcport = r.u16()?;
    let dstport = r.u16()?;
    // pad1
    r.skip(1)?;
    let tcp_flags = r.u8()?;
    let prot = r.u8()?;
    let tos = r.u8()?;
    let src_as = r.u16()?;
    let dst_as = r.u16()?;
    let src_mask = r.u8()?;
    let dst_mask = r.u8()?;
    // pad2
    r.skip(2)?;

    Ok(FlowRecord {
        srcaddr,
        dstaddr,
        nexthop,
        input,
        output,
        d_pkts,
        d_octets,
        first,
        last,
        srcport,
        dstport,
        tcp_flags,
        prot,
        tos,
        src_as,
        dst_as,
        src_mask,
        dst_mask,
    })
}

/// Converts every value before writing any, so that on error nothing is
/// written.
fn write_header(w: &mut Writer, header: &Header, records: usize) -> Result<(), WriteError> {
    let Header {
        version,
        count: _,
        sys_uptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval,
    } = *header;
    let count = u16::try_from(records).map_err(|_| WriteError::TooLarge {
        field: "count",
        value: records,
    })?;
    let sampling_interval = u16::try_from(sampling_interval)?;

    w.u16(version);
    w.u16(count);
    w.u32(sys_uptime);
    w.u32(unix_secs);
    w.u32(unix_nsecs);
    w.u32(flow_sequence);
    w.u8(engine_type);
    w.u8(engine_id);
    w.u16(sampling_interval);
    Ok(())
}

fn write_flow_record(w: &mut Writer, record: &FlowRecord) {
    let FlowRecord {
        srcaddr,
        dstaddr,
        nexthop,
        input,
        output,
        d_pkts,
        d_octets,
        first,
        last,
        srcport,
        dstport,
        tcp_flags,
        prot,
        tos,
        src_as,
        dst_as,
        src_mask,
        dst_mask,
    } = *record;
    w.ipv4(srcaddr);
    w.ipv4(dstaddr);
    w.ipv4(nexthop);
    w.u16(input);
    w.u16(output);
    w.u32(d_pkts);
    w.u32(d_octets);
    w.u32(first);
    w.u32(last);
    w.u16(srcport);
    w.u16(dstport);
    // pad1
    w.zeros(1);
    w.u8(tcp_flags);
    w.u8(prot);
    w.u8(tos);
    w.u16(src_as);
    w.u16(dst_as);
    w.u8(src_mask);
    w.u8(dst_mask);
    // pad2
    w.zeros(2);
}

#[cfg(test)]
mod tests {
    use rustflow_bytes::Truncated;

    use super::*;

    const HEADER_SIZE: usize = 24;
    const FLOW_RECORD_SIZE: usize = 48;

    fn header_bytes(count: u16) -> Vec<u8> {
        [
            &VERSION.to_be_bytes()[..],
            &count.to_be_bytes(),
            &3_600_000u32.to_be_bytes(),
            &1_700_000_000u32.to_be_bytes(),
            &123u32.to_be_bytes(),
            &42u32.to_be_bytes(),
            &[1, 2],
            &(1u16 << 14 | 100).to_be_bytes(),
        ]
        .concat()
    }

    /// Padding bytes are set, to show they are skipped whatever they hold.
    fn flow_record_bytes() -> Vec<u8> {
        [
            &[192, 0, 2, 1, 198, 51, 100, 1, 203, 0, 113, 1][..],
            &1u16.to_be_bytes(),
            &2u16.to_be_bytes(),
            &10u32.to_be_bytes(),
            &1500u32.to_be_bytes(),
            &3_540_000u32.to_be_bytes(),
            &3_599_000u32.to_be_bytes(),
            &1234u16.to_be_bytes(),
            &80u16.to_be_bytes(),
            &[0xee, 0x18, 6, 0x10],
            &64500u16.to_be_bytes(),
            &64501u16.to_be_bytes(),
            &[24, 16, 0xee, 0xee],
        ]
        .concat()
    }

    fn expected_header(count: u16) -> Header {
        Header {
            version: VERSION,
            count,
            sys_uptime: 3_600_000,
            unix_secs: 1_700_000_000,
            unix_nsecs: 123,
            flow_sequence: 42,
            engine_type: 1,
            engine_id: 2,
            sampling_interval: Sampling {
                mode: 1,
                interval: 100,
            },
        }
    }

    fn expected_flow_record() -> FlowRecord {
        FlowRecord {
            srcaddr: Ipv4Addr::new(192, 0, 2, 1),
            dstaddr: Ipv4Addr::new(198, 51, 100, 1),
            nexthop: Ipv4Addr::new(203, 0, 113, 1),
            input: 1,
            output: 2,
            d_pkts: 10,
            d_octets: 1500,
            first: 3_540_000,
            last: 3_599_000,
            srcport: 1234,
            dstport: 80,
            tcp_flags: 0x18,
            prot: 6,
            tos: 0x10,
            src_as: 64500,
            dst_as: 64501,
            src_mask: 24,
            dst_mask: 16,
        }
    }

    #[test]
    fn wire_sizes_match_the_format() {
        assert_eq!(header_bytes(0).len(), HEADER_SIZE);
        assert_eq!(flow_record_bytes().len(), FLOW_RECORD_SIZE);
    }

    #[test]
    fn parses_every_field() {
        let datagram = [header_bytes(2), flow_record_bytes(), flow_record_bytes()].concat();
        assert_eq!(
            parse(&datagram),
            Ok(Packet {
                header: expected_header(2),
                flow_records: vec![expected_flow_record(); 2],
            })
        );
    }

    #[test]
    fn the_sampling_field_splits_into_mode_and_interval() {
        let sampling = |mode, interval| Sampling { mode, interval };
        assert_eq!(Sampling::from(0), sampling(0, 0));
        assert_eq!(Sampling::from(100), sampling(0, 100));
        assert_eq!(Sampling::from(1 << 14 | 0x3fff), sampling(1, 0x3fff));
        assert_eq!(Sampling::from(2 << 14 | 1), sampling(2, 1));
        assert_eq!(Sampling::from(3 << 14), sampling(3, 0));
        assert_eq!(Sampling::from(u16::MAX), sampling(3, 0x3fff));
    }

    #[test]
    fn a_packet_may_carry_no_records() {
        let packet = parse(&header_bytes(0)).unwrap();
        assert!(packet.flow_records.is_empty());
    }

    #[test]
    fn bytes_after_the_last_record_are_ignored() {
        let datagram = [header_bytes(1), flow_record_bytes(), vec![0xff; 5]].concat();
        assert_eq!(parse(&datagram).unwrap().flow_records.len(), 1);
    }

    #[test]
    fn another_version_is_rejected() {
        let mut datagram = header_bytes(0);
        datagram[..2].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(parse(&datagram), Err(ParseError::Version(9)));
    }

    #[test]
    fn fewer_records_than_the_count_is_truncated() {
        let datagram = [header_bytes(2), flow_record_bytes()].concat();
        assert!(matches!(parse(&datagram), Err(ParseError::Truncated(_))));
    }

    #[test]
    fn a_short_header_is_truncated() {
        assert_eq!(
            parse(&header_bytes(0)[..HEADER_SIZE - 1]),
            Err(ParseError::Truncated(Truncated {
                requested: 2,
                available: 1
            }))
        );
    }

    /// What [`write`] makes of `flow_record_bytes`: padding as zeros.
    fn written_flow_record_bytes() -> Vec<u8> {
        let mut bytes = flow_record_bytes();
        bytes[36] = 0;
        bytes[46..].fill(0);
        bytes
    }

    #[test]
    fn writes_what_it_parses_with_zero_padding() {
        let datagram = [header_bytes(2), flow_record_bytes(), flow_record_bytes()].concat();
        let packet = parse(&datagram).unwrap();

        let mut written = Vec::new();
        write(&packet, &mut written).unwrap();

        assert_eq!(
            written,
            [
                header_bytes(2),
                written_flow_record_bytes(),
                written_flow_record_bytes()
            ]
            .concat()
        );
        assert_eq!(parse(&written), Ok(packet));
    }

    #[test]
    fn the_count_written_is_the_number_of_flow_records() {
        let mut packet = parse(&[header_bytes(1), flow_record_bytes()].concat()).unwrap();
        packet.header.count = 99;
        let mut written = vec![0xab];
        write(&packet, &mut written).unwrap();
        assert_eq!(written[0], 0xab);
        assert_eq!(written[3..5], 1u16.to_be_bytes());
        assert_eq!(written.len(), 1 + HEADER_SIZE + FLOW_RECORD_SIZE);
    }

    #[test]
    fn more_flow_records_than_a_count_holds_write_nothing() {
        let record = parse(&[header_bytes(1), flow_record_bytes()].concat())
            .unwrap()
            .flow_records
            .remove(0);
        let packet = Packet {
            header: expected_header(0),
            flow_records: vec![record; 65_536],
        };
        let mut written = Vec::new();
        assert_eq!(
            write(&packet, &mut written),
            Err(WriteError::TooLarge {
                field: "count",
                value: 65_536
            })
        );
        assert!(written.is_empty());
    }

    #[test]
    fn sampling_fields_round_trip_and_reject_values_too_wide() {
        for field in [0, 100, (1 << 14) | 100, u16::MAX] {
            assert_eq!(u16::try_from(Sampling::from(field)), Ok(field));
        }
        let too_wide = |mode, interval| u16::try_from(Sampling { mode, interval });
        assert_eq!(
            too_wide(4, 0),
            Err(WriteError::TooLarge {
                field: "sampling mode",
                value: 4
            })
        );
        assert_eq!(
            too_wide(0, 0x4000),
            Err(WriteError::TooLarge {
                field: "sampling interval",
                value: 0x4000
            })
        );

        let mut packet = parse(&header_bytes(0)).unwrap();
        packet.header.sampling_interval.mode = 4;
        let mut written = Vec::new();
        assert!(write(&packet, &mut written).is_err());
        assert!(written.is_empty());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn round_trips_through_serde() {
        let packet = parse(&[header_bytes(1), flow_record_bytes()].concat()).unwrap();
        let json = serde_json::to_value(&packet).unwrap();
        assert_eq!(
            json["sampling_interval"],
            serde_json::json!({ "mode": 1, "interval": 100 })
        );
        assert_eq!(json["flow_records"][0]["srcaddr"], "192.0.2.1");
        assert_eq!(serde_json::from_value::<Packet>(json).unwrap(), packet);
    }
}
