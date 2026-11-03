use std::net::Ipv4Addr;
use std::time::Duration;

use super::*;
use crate::information_element::Registry;
use crate::value::Value;
use crate::{DataSet, Error};

const SOURCE_ID: u32 = 7;
const OCTET_DELTA_COUNT: u16 = 1;
const PACKET_DELTA_COUNT: u16 = 2;
const IPV4_SRC_ADDR: u16 = 8;
const SAMPLING_INTERVAL: u16 = 34;
const SYSTEM_SCOPE: u16 = 1;

fn parser() -> Parser {
    Parser::new(Registry::iana(), Duration::from_mins(10))
}

fn packet(source_id: u32, flow_sets: &[Vec<u8>]) -> Vec<u8> {
    let header = [
        &VERSION.to_be_bytes()[..],
        &3u16.to_be_bytes(),
        &3_600_000u32.to_be_bytes(),
        &1_700_000_000u32.to_be_bytes(),
        &42u32.to_be_bytes(),
        &source_id.to_be_bytes(),
    ]
    .concat();
    [header, flow_sets.concat()].concat()
}

fn flow_set(id: u16, body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(FLOW_SET_HEADER_SIZE + body.len()).unwrap();
    [&id.to_be_bytes()[..], &length.to_be_bytes(), body].concat()
}

fn fields(fields: &[(u16, u16)]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|(field_type, length)| [field_type.to_be_bytes(), length.to_be_bytes()])
        .flatten()
        .collect()
}

fn template(template_id: u16, template_fields: &[(u16, u16)]) -> Vec<u8> {
    let field_count = u16::try_from(template_fields.len()).unwrap();
    [
        &template_id.to_be_bytes()[..],
        &field_count.to_be_bytes(),
        &fields(template_fields),
    ]
    .concat()
}

fn options_template(template_id: u16, scope: &[(u16, u16)], options: &[(u16, u16)]) -> Vec<u8> {
    let (scope, options) = (fields(scope), fields(options));
    [
        &template_id.to_be_bytes()[..],
        &u16::try_from(scope.len()).unwrap().to_be_bytes(),
        &u16::try_from(options.len()).unwrap().to_be_bytes(),
        &scope,
        &options,
    ]
    .concat()
}

fn octet_count_template() -> Vec<u8> {
    flow_set(
        TEMPLATE_FLOW_SET_ID,
        &template(256, &[(OCTET_DELTA_COUNT, 4)]),
    )
}

fn octet_count_data(count: u32) -> Vec<u8> {
    flow_set(256, &count.to_be_bytes())
}

fn data_set(flow_set: &FlowSet) -> &DataSet<Template> {
    let FlowSet::Data(data) = flow_set else {
        panic!("expected a data FlowSet, got {flow_set:?}");
    };
    data
}

#[test]
fn parses_the_header() {
    let packet = parser().parse(&packet(SOURCE_ID, &[])).unwrap();
    assert_eq!(
        packet.header,
        Header {
            version: VERSION,
            count: 3,
            sys_uptime: 3_600_000,
            unix_secs: 1_700_000_000,
            sequence_number: 42,
            source_id: SOURCE_ID,
        }
    );
    assert!(packet.flow_sets.is_empty());
}

#[test]
fn another_version_is_rejected() {
    let mut datagram = packet(SOURCE_ID, &[]);
    datagram[..2].copy_from_slice(&10u16.to_be_bytes());
    assert_eq!(parser().parse(&datagram), Err(Error::Version(10)));
}

#[test]
fn data_decodes_by_the_template_sent_before_it() {
    let template = flow_set(
        TEMPLATE_FLOW_SET_ID,
        &template(
            256,
            &[
                (IPV4_SRC_ADDR, 4),
                (OCTET_DELTA_COUNT, 4),
                (PACKET_DELTA_COUNT, 8),
            ],
        ),
    );
    let record = [
        &[192, 0, 2, 1][..],
        &1500u32.to_be_bytes(),
        &10u64.to_be_bytes(),
    ]
    .concat();
    let data = flow_set(256, &[record.clone(), record].concat());

    let packet = parser()
        .parse(&packet(SOURCE_ID, &[data.clone(), template, data]))
        .unwrap();

    assert_eq!(packet.flow_sets[0], FlowSet::Unknown(256));
    let FlowSet::Templates(templates) = &packet.flow_sets[1] else {
        panic!("expected a template FlowSet");
    };
    let data = data_set(&packet.flow_sets[2]);
    assert!(Arc::ptr_eq(&templates[0], &data.template));
    let values = vec![
        Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
        Value::Unsigned32(1500),
        Value::Unsigned64(10),
    ];
    assert_eq!(data.records, [values.clone(), values]);
}

#[test]
fn unknown_field_types_keep_their_bytes() {
    let template = flow_set(TEMPLATE_FLOW_SET_ID, &template(256, &[(0xffff, 3)]));
    let data = flow_set(256, &[0xaa, 0xbb, 0xcc]);
    let packet = parser()
        .parse(&packet(SOURCE_ID, &[template, data]))
        .unwrap();
    assert_eq!(
        data_set(&packet.flow_sets[1]).records,
        [[Value::OctetArray(vec![0xaa, 0xbb, 0xcc])]]
    );
}

#[test]
fn templates_are_kept_per_source_id_across_packets() {
    let mut parser = parser();
    parser
        .parse(&packet(SOURCE_ID, &[octet_count_template()]))
        .unwrap();

    let other_source = parser.parse(&packet(8, &[octet_count_data(42)])).unwrap();
    assert_eq!(other_source.flow_sets, [FlowSet::Unknown(256)]);

    let same_source = parser
        .parse(&packet(SOURCE_ID, &[octet_count_data(42)]))
        .unwrap();
    assert_eq!(
        data_set(&same_source.flow_sets[0]).records,
        [[Value::Unsigned32(42)]]
    );
}

#[test]
fn a_resent_template_replaces_the_old_one_at_once() {
    let mut parser = parser();
    let first = parser
        .parse(&packet(
            SOURCE_ID,
            &[octet_count_template(), octet_count_data(42)],
        ))
        .unwrap();
    let replacement = flow_set(
        TEMPLATE_FLOW_SET_ID,
        &template(256, &[(PACKET_DELTA_COUNT, 4)]),
    );
    let second = parser
        .parse(&packet(SOURCE_ID, &[replacement, octet_count_data(42)]))
        .unwrap();

    let field_type = |packet: &Packet| data_set(&packet.flow_sets[1]).template.fields[0].field_type;
    assert_eq!(field_type(&first), OCTET_DELTA_COUNT);
    assert_eq!(field_type(&second), PACKET_DELTA_COUNT);
}

#[test]
fn expired_templates_do_not_decode_data() {
    let mut parser = Parser::new(Registry::empty(), Duration::ZERO);
    let packet = parser
        .parse(&packet(
            SOURCE_ID,
            &[octet_count_template(), octet_count_data(42)],
        ))
        .unwrap();
    assert_eq!(packet.flow_sets[1], FlowSet::Unknown(256));
}

#[test]
fn options_data_decodes_scope_values_before_option_values() {
    let template = flow_set(
        OPTIONS_TEMPLATE_FLOW_SET_ID,
        &[
            options_template(257, &[(SYSTEM_SCOPE, 4)], &[(SAMPLING_INTERVAL, 4)]),
            vec![0; 2],
        ]
        .concat(),
    );
    let data = flow_set(
        257,
        &[&7u32.to_be_bytes()[..], &100u32.to_be_bytes()].concat(),
    );

    let packet = parser()
        .parse(&packet(SOURCE_ID, &[template, data]))
        .unwrap();

    let FlowSet::OptionsTemplates(templates) = &packet.flow_sets[0] else {
        panic!("expected an options template FlowSet");
    };
    assert_eq!(
        *templates[0],
        OptionsTemplate {
            template_id: 257,
            scope_fields: vec![Field {
                field_type: SYSTEM_SCOPE,
                length: 4
            }],
            option_fields: vec![Field {
                field_type: SAMPLING_INTERVAL,
                length: 4
            }],
        }
    );
    let FlowSet::OptionsData(data) = &packet.flow_sets[1] else {
        panic!("expected an options data FlowSet");
    };
    assert!(Arc::ptr_eq(&templates[0], &data.template));
    assert_eq!(
        data.records,
        [[Value::Unsigned32(7), Value::Unsigned32(100)]]
    );
}

#[test]
fn a_template_id_can_move_between_template_kinds() {
    let mut parser = parser();
    parser
        .parse(&packet(SOURCE_ID, &[octet_count_template()]))
        .unwrap();
    let options = flow_set(
        OPTIONS_TEMPLATE_FLOW_SET_ID,
        &options_template(256, &[(SYSTEM_SCOPE, 4)], &[]),
    );
    let packet = parser
        .parse(&packet(SOURCE_ID, &[options, octet_count_data(7)]))
        .unwrap();
    assert!(matches!(packet.flow_sets[1], FlowSet::OptionsData(_)));
}

#[test]
fn padding_does_not_become_records_or_templates() {
    let template = flow_set(
        TEMPLATE_FLOW_SET_ID,
        &[template(256, &[(OCTET_DELTA_COUNT, 8)]), vec![0; 4]].concat(),
    );
    let data = flow_set(
        256,
        &[&42u64.to_be_bytes()[..], &43u64.to_be_bytes(), &[0; 4]].concat(),
    );

    let packet = parser()
        .parse(&packet(
            SOURCE_ID,
            &[template, data, octet_count_template()],
        ))
        .unwrap();

    let FlowSet::Templates(templates) = &packet.flow_sets[0] else {
        panic!("expected a template FlowSet");
    };
    assert_eq!(templates.len(), 1);
    assert_eq!(
        data_set(&packet.flow_sets[1]).records,
        [[Value::Unsigned64(42)], [Value::Unsigned64(43)]]
    );
    assert!(matches!(packet.flow_sets[2], FlowSet::Templates(_)));
}

#[test]
fn a_template_without_fields_yields_no_records() {
    let template = flow_set(TEMPLATE_FLOW_SET_ID, &template(256, &[]));
    let packet = parser()
        .parse(&packet(
            SOURCE_ID,
            &[template, flow_set(256, &[0; 4]), octet_count_template()],
        ))
        .unwrap();
    assert!(data_set(&packet.flow_sets[1]).records.is_empty());
    assert_eq!(packet.flow_sets.len(), 3);
}

#[test]
fn reserved_flow_set_ids_are_unknown() {
    let packet = parser()
        .parse(&packet(SOURCE_ID, &[flow_set(2, &[1, 2, 3, 4])]))
        .unwrap();
    assert_eq!(packet.flow_sets, [FlowSet::Unknown(2)]);
}

#[test]
fn parsing_stops_at_a_truncated_flow_set() {
    let mut truncated = octet_count_data(42);
    truncated.truncate(6);
    let mut parser = parser();
    let parsed = parser
        .parse(&packet(SOURCE_ID, &[octet_count_template(), truncated]))
        .unwrap();

    assert_eq!(parsed.flow_sets.len(), 1);
    let later = parser
        .parse(&packet(SOURCE_ID, &[octet_count_data(42)]))
        .unwrap();
    assert!(matches!(later.flow_sets[0], FlowSet::Data(_)));
}

#[test]
fn parsing_stops_at_a_flow_set_shorter_than_its_header() {
    let short = [&256u16.to_be_bytes()[..], &3u16.to_be_bytes()].concat();
    let packet = parser()
        .parse(&packet(
            SOURCE_ID,
            &[octet_count_template(), short, octet_count_template()],
        ))
        .unwrap();
    assert_eq!(packet.flow_sets.len(), 1);
}

#[cfg(feature = "serde")]
#[test]
fn round_trips_through_serde() {
    let packet = parser()
        .parse(&packet(
            SOURCE_ID,
            &[octet_count_template(), octet_count_data(42)],
        ))
        .unwrap();
    let json = serde_json::to_value(&packet).unwrap();
    assert_eq!(json["source_id"], SOURCE_ID);
    assert_eq!(
        json["flow_sets"][1]["Data"]["records"],
        serde_json::json!([[{ "Unsigned32": 42 }]])
    );
    assert_eq!(serde_json::from_value::<Packet>(json).unwrap(), packet);
}
