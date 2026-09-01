use std::net::Ipv4Addr;

use chrono::DateTime;
use hex_literal::hex;
use rustflow_core::common::information_element::InformationElement::*;
use rustflow_core::ipfix::encoder::Encode;
use rustflow_core::ipfix::parser::{
    DataRecord, FieldSpecifier, FieldValue, IpfixPacket, Record, Set, TemplateRecord,
};

// RFC 7011, Appendix A.2.1 and A.3, with unspecified header values set to zero.
// https://www.rfc-editor.org/rfc/rfc7011.html#appendix-A
const RFC_7011_TEMPLATE_AND_DATA: &[u8] = &hex!(
    // Message Header: version 10, length 108, export time 0, sequence 0,
    // observation domain 1.
    "000a 006c 0000 0000 0000 0000 0000 0001"
    // Template Set header: Set ID 2, length 28.
    "0002 001c"
    // Template 256: five fields.
    "0100 0005"
    // sourceIPv4Address(8), destinationIPv4Address(12),
    // ipNextHopIPv4Address(15), packetDeltaCount(2), octetDeltaCount(1).
    "0008 0004 000c 0004 000f 0004 0002 0004 0001 0004"
    // Data Set header: Template ID 256, length 64.
    "0100 0040"
    // Data Record 1: addresses, 5009 packets, 5,344,385 octets.
    "c000 020c c000 02fe c000 0201 0000 1391 0051 8c81"
    // Data Record 2: addresses, 748 packets, 388,934 octets.
    "c000 021b c000 0217 c000 0202 0000 02ec 0005 ef46"
    // Data Record 3: addresses, 5 packets, 6,534 octets.
    "c000 0238 c000 0241 c000 0203 0000 0005 0000 1986"
);

fn ip(a: u8, b: u8, c: u8, d: u8) -> FieldValue {
    FieldValue::Ipv4Address(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn encoder_reproduces_rfc_7011_appendix_a_vector() {
    let packet = IpfixPacket::new(
        DateTime::from_timestamp(0, 0).unwrap(),
        0,
        1,
        vec![
            Set::new(
                2,
                vec![Record::Template(TemplateRecord::new(
                    256,
                    vec![
                        FieldSpecifier::from_ie(SourceIpv4Address, 4),
                        FieldSpecifier::from_ie(DestinationIpv4Address, 4),
                        FieldSpecifier::from_ie(IpNextHopIpv4Address, 4),
                        FieldSpecifier::from_ie(PacketDeltaCount, 4),
                        FieldSpecifier::from_ie(OctetDeltaCount, 4),
                    ],
                ))],
            ),
            Set::new(
                256,
                vec![
                    Record::Data(DataRecord::new(vec![
                        ip(192, 0, 2, 12),
                        ip(192, 0, 2, 254),
                        ip(192, 0, 2, 1),
                        FieldValue::Unsigned32(5009),
                        FieldValue::Unsigned32(5_344_385),
                    ])),
                    Record::Data(DataRecord::new(vec![
                        ip(192, 0, 2, 27),
                        ip(192, 0, 2, 23),
                        ip(192, 0, 2, 2),
                        FieldValue::Unsigned32(748),
                        FieldValue::Unsigned32(388_934),
                    ])),
                    Record::Data(DataRecord::new(vec![
                        ip(192, 0, 2, 56),
                        ip(192, 0, 2, 65),
                        ip(192, 0, 2, 3),
                        FieldValue::Unsigned32(5),
                        FieldValue::Unsigned32(6_534),
                    ])),
                ],
            ),
        ],
    );

    let mut built = Vec::new();
    packet.encode(&mut built);

    assert_eq!(hex::encode(&built), hex::encode(RFC_7011_TEMPLATE_AND_DATA));
}
