//! NetFlow v5: a fixed 24-byte header followed by `count` fixed 48-byte flow
//! records.

use std::net::Ipv4Addr;

use rustflow_reader::Reader;

use crate::Error;

pub const VERSION: u16 = 5;

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
            interval: field & 0x3fff,
        }
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
pub fn parse(datagram: &[u8]) -> Result<Packet, Error> {
    let mut r = Reader::new(datagram);
    let header = parse_header(&mut r)?;
    let flow_records = r.repeat(usize::from(header.count), parse_flow_record)?;

    Ok(Packet {
        header,
        flow_records,
    })
}

fn parse_header(r: &mut Reader) -> Result<Header, Error> {
    let version = r.u16()?;
    if version != VERSION {
        return Err(Error::Version(version.into()));
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

fn parse_flow_record(r: &mut Reader) -> Result<FlowRecord, Error> {
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

#[cfg(test)]
mod tests {
    use rustflow_reader::Truncated;

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
        assert_eq!(parse(&datagram), Err(Error::Version(9)));
    }

    #[test]
    fn fewer_records_than_the_count_is_truncated() {
        let datagram = [header_bytes(2), flow_record_bytes()].concat();
        assert!(matches!(parse(&datagram), Err(Error::Truncated(_))));
    }

    #[test]
    fn a_short_header_is_truncated() {
        assert_eq!(
            parse(&header_bytes(0)[..HEADER_SIZE - 1]),
            Err(Error::Truncated(Truncated {
                requested: 2,
                available: 1
            }))
        );
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
