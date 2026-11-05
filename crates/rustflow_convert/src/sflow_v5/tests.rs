use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use etherparse::{PacketBuilder, VlanId};
use rustflow_protocol::sflow_v5::{self, CountersSample, DataSource, Header};

use super::*;
use crate::fixtures::udp_payloads;

const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const NO_INTERFACE: Interface = Interface {
    format: 0,
    value: 0,
};

fn flow_sample(records: Vec<FlowRecord>) -> FlowSample {
    FlowSample {
        sequence_number: 1,
        source_id: DataSource {
            source_id_type: 0,
            source_id_index: 3,
        },
        sampling_rate: 1000,
        sample_pool: 0,
        drops: 0,
        input: NO_INTERFACE,
        output: NO_INTERFACE,
        records,
    }
}

fn converted(samples: Vec<Sample>) -> Vec<Record> {
    let packet = Packet {
        header: Header {
            version: sflow_v5::VERSION,
            agent_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            sub_agent_id: 4,
            sequence_number: 42,
            uptime: 0,
        },
        samples,
    };
    let received = Received {
        exporter: SocketAddr::from(([192, 0, 2, 254], 6343)),
        time: None,
    };
    let mut records = Vec::new();
    convert(packet, &received, &mut records);
    records
}

fn converted_flow(records: Vec<FlowRecord>) -> Record {
    converted(vec![Sample::Flow(flow_sample(records))]).remove(0)
}

fn sampled_ipv4() -> FlowRecord {
    FlowRecord::SampledIpv4(SampledIpv4 {
        length: 1500,
        protocol: 6,
        src_ip: SRC,
        dst_ip: DST,
        src_port: 1234,
        dst_port: 80,
        tcp_flags: 0x18,
        tos: 0,
    })
}

fn sampled_header(protocol: HeaderProtocol, header: Vec<u8>) -> FlowRecord {
    FlowRecord::SampledHeader(SampledHeader {
        protocol,
        frame_length: 1518,
        stripped: 4,
        header,
    })
}

#[test]
fn a_flow_sample_is_one_randomly_sampled_packet() {
    let record = converted_flow(vec![sampled_ipv4()]);

    assert_eq!(record.protocol, Protocol::SflowV5);
    assert_eq!(record.sequence_number, 42);
    assert_eq!(
        record.first(iana::PACKET_DELTA_COUNT),
        Some(&Value::Unsigned64(1))
    );
    assert_eq!(
        record.first(iana::OCTET_DELTA_COUNT),
        Some(&Value::Unsigned64(1500))
    );
    assert_eq!(
        record.first(iana::SOURCE_IPV4_ADDRESS),
        Some(&Value::Ipv4Address(SRC))
    );
    assert_eq!(
        record.first(iana::TCP_CONTROL_BITS),
        Some(&Value::Unsigned16(0x18))
    );
    assert_eq!(
        record.first(iana::SELECTOR_ALGORITHM),
        Some(&Value::Unsigned16(3))
    );
    assert_eq!(
        record.first(iana::SAMPLING_POPULATION),
        Some(&Value::Unsigned32(1000))
    );
    assert_eq!(
        record.first(iana::EXPORTER_IPV4_ADDRESS),
        Some(&Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 10)))
    );
    assert_eq!(
        record.first(iana::ORIGINAL_OBSERVATION_DOMAIN_ID),
        Some(&Value::Unsigned32(4))
    );
}

#[test]
fn only_flow_samples_are_records_and_alike_ones_share_elements() {
    let counters = Sample::Counters(CountersSample {
        sequence_number: 1,
        source_id: DataSource {
            source_id_type: 0,
            source_id_index: 3,
        },
        records: Vec::new(),
    });
    let flow = || Sample::Flow(flow_sample(vec![sampled_ipv4()]));
    let records = converted(vec![flow(), counters, flow()]);

    assert_eq!(records.len(), 2);
    assert!(Arc::ptr_eq(&records[0].elements, &records[1].elements));
}

#[test]
fn only_an_if_index_is_an_interface() {
    let interfaces = |input: Interface, output: Interface, compact: bool| {
        let sample = FlowSample {
            input,
            output,
            ..flow_sample(Vec::new())
        };
        let record = converted(vec![if compact {
            Sample::Flow(sample)
        } else {
            Sample::ExpandedFlow(sample)
        }])
        .remove(0);
        (
            record.first(iana::INGRESS_INTERFACE).cloned(),
            record.first(iana::EGRESS_INTERFACE).cloned(),
        )
    };
    let interface = |format, value| Interface { format, value };
    let internal = interface(0, INTERNAL_INTERFACE);

    assert_eq!(
        interfaces(interface(0, 7), interface(0, 9), true),
        (Some(Value::Unsigned32(7)), Some(Value::Unsigned32(9)))
    );
    // Dropped with reason 2, and sent out of 3 interfaces.
    assert_eq!(
        interfaces(interface(1, 2), interface(2, 3), true),
        (None, None)
    );
    assert_eq!(interfaces(internal, NO_INTERFACE, true), (None, None));
    assert_eq!(
        interfaces(internal, NO_INTERFACE, false),
        (Some(Value::Unsigned32(INTERNAL_INTERFACE)), None)
    );
}

#[test]
fn extended_records_add_routing_and_vlans() {
    let router = FlowRecord::ExtendedRouter(ExtendedRouter {
        nexthop: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        src_mask_len: 24,
        dst_mask_len: 16,
    });
    let switch = FlowRecord::ExtendedSwitch(ExtendedSwitch {
        src_vlan: 10,
        src_priority: 0,
        dst_vlan: u32::MAX,
        dst_priority: 0,
    });
    let gateway = |dst_as_path| {
        FlowRecord::ExtendedGateway(ExtendedGateway {
            nexthop: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            r#as: 65000,
            src_as: 64496,
            src_peer_as: 64497,
            dst_as_path,
            communities: Vec::new(),
            localpref: 100,
        })
    };
    // The router record comes before the addresses its prefixes are of.
    let record = converted_flow(vec![
        router,
        switch,
        gateway(vec![AsPathSegment::AsSequence(vec![64498, 64499])]),
        sampled_ipv4(),
    ]);

    assert_eq!(
        record.first(iana::IP_NEXT_HOP_IPV4_ADDRESS),
        Some(&Value::Ipv4Address(Ipv4Addr::new(203, 0, 113, 1)))
    );
    assert_eq!(
        record.first(iana::SOURCE_IPV4_PREFIX_LENGTH),
        Some(&Value::Unsigned8(24))
    );
    assert_eq!(
        record.first(iana::DESTINATION_IPV4_PREFIX_LENGTH),
        Some(&Value::Unsigned8(16))
    );
    assert_eq!(record.first(iana::VLAN_ID), Some(&Value::Unsigned16(10)));
    assert_eq!(record.first(iana::POST_VLAN_ID), None);
    assert_eq!(
        record.first(iana::BGP_NEXT_HOP_IPV6_ADDRESS),
        Some(&Value::Ipv6Address(Ipv6Addr::LOCALHOST))
    );
    assert_eq!(
        record.first(iana::BGP_SOURCE_AS_NUMBER),
        Some(&Value::Unsigned32(64496))
    );
    assert_eq!(
        record.first(iana::BGP_DESTINATION_AS_NUMBER),
        Some(&Value::Unsigned32(64499))
    );

    let ending_in_a_set = converted_flow(vec![gateway(vec![
        AsPathSegment::AsSequence(vec![64498]),
        AsPathSegment::AsSet(vec![64499, 64500]),
    ])]);
    assert_eq!(
        ending_in_a_set.first(iana::BGP_DESTINATION_AS_NUMBER),
        Some(&Value::Unsigned32(0))
    );
}

#[test]
fn a_sampled_frame_is_dissected() {
    let mut frame = Vec::new();
    PacketBuilder::ethernet2(MAC, [4; 6])
        .single_vlan(VlanId::try_new(20).unwrap())
        .ipv4(SRC.octets(), DST.octets(), 64)
        .tcp(1234, 80, 0, 1024)
        .syn()
        .write(&mut frame, &[0; 8])
        .unwrap();
    let record = converted_flow(vec![sampled_header(
        HeaderProtocol::EthernetIso88023,
        frame,
    )]);

    assert_eq!(
        record.first(iana::LAYER2_OCTET_DELTA_COUNT),
        Some(&Value::Unsigned64(1518))
    );
    assert_eq!(record.first(iana::OCTET_DELTA_COUNT), None);
    assert_eq!(
        record.first(iana::SOURCE_MAC_ADDRESS),
        Some(&Value::MacAddress(MAC))
    );
    assert_eq!(
        record.first(iana::DOT1Q_VLAN_ID),
        Some(&Value::Unsigned16(20))
    );
    assert_eq!(
        record.first(iana::ETHERNET_TYPE),
        Some(&Value::Unsigned16(0x0800))
    );
    assert_eq!(
        record.first(iana::SOURCE_IPV4_ADDRESS),
        Some(&Value::Ipv4Address(SRC))
    );
    assert_eq!(record.first(iana::IP_TTL), Some(&Value::Unsigned8(64)));
    assert_eq!(
        record.first(iana::PROTOCOL_IDENTIFIER),
        Some(&Value::Unsigned8(6))
    );
    assert_eq!(
        record.first(iana::DESTINATION_TRANSPORT_PORT),
        Some(&Value::Unsigned16(80))
    );
    assert_eq!(
        record.first(iana::TCP_CONTROL_BITS),
        Some(&Value::Unsigned16(0x02))
    );
}

#[test]
fn a_sampled_ip_packet_counts_ip_octets_through_its_tunnel() {
    let mut inner = Vec::new();
    PacketBuilder::ipv6(
        Ipv6Addr::LOCALHOST.octets(),
        Ipv6Addr::LOCALHOST.octets(),
        64,
    )
    .icmpv6_echo_request(1, 1)
    .write(&mut inner, &[])
    .unwrap();
    // GRE without options, carrying IPv6.
    let gre = [&[0, 0, 0x86, 0xdd][..], &inner].concat();
    let mut packet = Vec::new();
    PacketBuilder::ipv4(SRC.octets(), DST.octets(), 64)
        .write(&mut packet, etherparse::IpNumber::GRE, &gre)
        .unwrap();
    let record = converted_flow(vec![sampled_header(HeaderProtocol::Ipv4, packet)]);

    assert_eq!(
        record.first(iana::OCTET_DELTA_COUNT),
        Some(&Value::Unsigned64(1518))
    );
    assert_eq!(
        record.first(iana::SOURCE_IPV6_ADDRESS),
        Some(&Value::Ipv6Address(Ipv6Addr::LOCALHOST))
    );
    assert_eq!(record.first(iana::SOURCE_IPV4_ADDRESS), None);
    assert_eq!(
        record.first(iana::ETHERNET_TYPE),
        Some(&Value::Unsigned16(0x86dd))
    );
    assert_eq!(
        record.first(iana::ICMP_TYPE_IPV6),
        Some(&Value::Unsigned8(128))
    );
}

#[test]
fn the_first_record_to_describe_the_packet_wins() {
    let mut packet = Vec::new();
    PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(53, 53)
        .write(&mut packet, &[])
        .unwrap();
    let record = converted_flow(vec![
        sampled_ipv4(),
        sampled_header(HeaderProtocol::Ipv4, packet),
    ]);

    assert_eq!(record.all(iana::SOURCE_IPV4_ADDRESS).count(), 1);
    assert_eq!(
        record.first(iana::SOURCE_IPV4_ADDRESS),
        Some(&Value::Ipv4Address(SRC))
    );
    assert_eq!(
        record.first(iana::OCTET_DELTA_COUNT),
        Some(&Value::Unsigned64(1500))
    );
    // What only the header gives is still added.
    assert_eq!(record.first(iana::IP_TTL), Some(&Value::Unsigned8(64)));
}

#[test]
fn real_datagrams_convert_their_flow_samples() {
    let mut records = Vec::new();
    let mut flow_samples = 0;
    let received = Received {
        exporter: SocketAddr::from(([192, 0, 2, 10], 6343)),
        time: None,
    };
    for datagram in udp_payloads("sflow_v5_sanity.pcap") {
        let packet = sflow_v5::parse(&datagram).unwrap();
        flow_samples += packet
            .samples
            .iter()
            .filter(|sample| matches!(sample, Sample::Flow(_) | Sample::ExpandedFlow(_)))
            .count();
        convert(packet, &received, &mut records);
    }

    assert!(flow_samples > 0);
    assert_eq!(records.len(), flow_samples);
    for record in &records {
        assert_eq!(record.values.len(), record.elements.len());
    }
    let first = &records[0];
    assert_eq!(
        first.first(iana::LAYER2_OCTET_DELTA_COUNT),
        Some(&Value::Unsigned64(1518))
    );
    assert_eq!(
        first.first(iana::SAMPLING_POPULATION),
        Some(&Value::Unsigned32(2000))
    );
    assert!(first.first(iana::SOURCE_IPV4_ADDRESS).is_some());
}
