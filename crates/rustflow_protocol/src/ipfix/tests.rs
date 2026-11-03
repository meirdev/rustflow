use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::time::Duration;

use super::*;
use crate::information_element::{DataType, DataTypeSemantics, InformationElement, Registry};
use crate::value::Value;
use crate::{DataSet, ParseError};

const DOMAIN: u32 = 7;
const OCTET_DELTA_COUNT: u16 = 1;
const SOURCE_IPV4_ADDRESS: u16 = 8;
const SAMPLING_INTERVAL: u16 = 34;
const INTERFACE_NAME: u16 = 82;
const OBSERVATION_DOMAIN_ID: u16 = 149;
const BASIC_LIST: u16 = 291;
const SUB_TEMPLATE_LIST: u16 = 292;
const SUB_TEMPLATE_MULTI_LIST: u16 = 293;
const INFORMATION_ELEMENT_ID: u16 = 303;
const INFORMATION_ELEMENT_DATA_TYPE: u16 = 339;
const INFORMATION_ELEMENT_NAME: u16 = 341;
const INFORMATION_ELEMENT_SEMANTICS: u16 = 344;
const PRIVATE_ENTERPRISE_NUMBER: u16 = 346;
const TYPE_TEMPLATE_ID: u16 = 400;
const VENDOR_ENTERPRISE_NUMBER: u32 = 9;
const VENDOR_FIELD: FieldSpecifier = FieldSpecifier {
    information_element_id: 1,
    field_length: 4,
    enterprise_number: Some(VENDOR_ENTERPRISE_NUMBER),
};

fn message(domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    let sets = sets.concat();
    let length = u16::try_from(HEADER_SIZE + sets.len()).unwrap();
    [
        &VERSION.to_be_bytes()[..],
        &length.to_be_bytes(),
        &1_700_000_000u32.to_be_bytes(),
        &42u32.to_be_bytes(),
        &domain.to_be_bytes(),
        &sets,
    ]
    .concat()
}

fn set(id: u16, body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(SET_HEADER_SIZE + body.len()).unwrap();
    [&id.to_be_bytes()[..], &length.to_be_bytes(), body].concat()
}

fn field(id: u16, length: u16) -> Vec<u8> {
    [id.to_be_bytes(), length.to_be_bytes()].concat()
}

fn enterprise_field(id: u16, length: u16, enterprise_number: u32) -> Vec<u8> {
    [
        &(id | ENTERPRISE_BIT).to_be_bytes()[..],
        &length.to_be_bytes(),
        &enterprise_number.to_be_bytes(),
    ]
    .concat()
}

fn template(template_id: u16, fields: &[Vec<u8>]) -> Vec<u8> {
    let field_count = u16::try_from(fields.len()).unwrap();
    [
        &template_id.to_be_bytes()[..],
        &field_count.to_be_bytes(),
        &fields.concat(),
    ]
    .concat()
}

fn options_template(template_id: u16, scope_field_count: u16, fields: &[Vec<u8>]) -> Vec<u8> {
    let field_count = u16::try_from(fields.len()).unwrap();
    [
        &template_id.to_be_bytes()[..],
        &field_count.to_be_bytes(),
        &scope_field_count.to_be_bytes(),
        &fields.concat(),
    ]
    .concat()
}

fn variable(value: &[u8]) -> Vec<u8> {
    match u8::try_from(value.len()) {
        Ok(length) if length < 255 => [&[length][..], value].concat(),
        _ => [
            &[255][..],
            &u16::try_from(value.len()).unwrap().to_be_bytes(),
            value,
        ]
        .concat(),
    }
}

fn octet_count_template() -> Vec<u8> {
    set(
        TEMPLATE_SET_ID,
        &template(256, &[field(OCTET_DELTA_COUNT, 4)]),
    )
}

fn octet_count_data(count: u32) -> Vec<u8> {
    set(256, &count.to_be_bytes())
}

fn data_set(set: &Set) -> &DataSet<Template> {
    let Set::Data(data) = set else {
        panic!("expected a data set, got {set:?}");
    };
    data
}

/// The value of the first field of the first record in the last set.
fn only_value(packet: &Packet) -> &Value {
    &data_set(packet.sets.last().unwrap()).records[0][0]
}

#[test]
fn parses_the_header() {
    let packet = Parser::default().parse(&message(DOMAIN, &[])).unwrap();
    assert_eq!(
        packet.header,
        Header {
            version: VERSION,
            length: 16,
            export_time: 1_700_000_000,
            sequence_number: 42,
            observation_domain_id: DOMAIN,
        }
    );
    assert!(packet.sets.is_empty());
}

#[test]
fn another_version_is_rejected() {
    let mut datagram = message(DOMAIN, &[]);
    datagram[..2].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(
        Parser::default().parse(&datagram),
        Err(ParseError::Version(9))
    );
}

#[test]
fn the_message_length_bounds_the_sets() {
    let mut datagram = message(DOMAIN, &[octet_count_template()]);
    datagram.extend([0xff; 3]);
    assert_eq!(Parser::default().parse(&datagram).unwrap().sets.len(), 1);

    let mut short = message(DOMAIN, &[]);
    short[2..4].copy_from_slice(&15u16.to_be_bytes());
    assert_eq!(
        Parser::default().parse(&short),
        Err(ParseError::MessageLength(15))
    );

    let mut long = message(DOMAIN, &[]);
    long[2..4].copy_from_slice(&20u16.to_be_bytes());
    assert!(matches!(
        Parser::default().parse(&long),
        Err(ParseError::Truncated(_))
    ));
}

#[test]
fn data_decodes_by_the_template_sent_before_it() {
    let template = set(
        TEMPLATE_SET_ID,
        &template(
            256,
            &[field(SOURCE_IPV4_ADDRESS, 4), field(OCTET_DELTA_COUNT, 8)],
        ),
    );
    let record = [&[192, 0, 2, 1][..], &1500u64.to_be_bytes()].concat();
    let data = set(256, &[record.clone(), record].concat());

    let packet = Parser::default()
        .parse(&message(DOMAIN, &[data.clone(), template, data]))
        .unwrap();

    assert_eq!(packet.sets[0], Set::Unknown(256));
    let Set::Templates(templates) = &packet.sets[1] else {
        panic!("expected a template set");
    };
    let data = data_set(&packet.sets[2]);
    assert!(Arc::ptr_eq(&templates[0], &data.template));
    let values = vec![
        Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)),
        Value::Unsigned64(1500),
    ];
    assert_eq!(data.records, [values.clone(), values]);
}

#[test]
fn enterprise_fields_are_looked_up_by_their_enterprise_number() {
    let template = set(
        TEMPLATE_SET_ID,
        &template(
            256,
            &[enterprise_field(1, 4, 9), field(OCTET_DELTA_COUNT, 4)],
        ),
    );
    let data = set(256, &[0, 0, 0, 5, 0, 0, 0, 6]);
    let datagram = message(DOMAIN, &[template, data]);

    let packet = Parser::default().parse(&datagram).unwrap();
    let Set::Templates(templates) = &packet.sets[0] else {
        panic!("expected a template set");
    };
    assert_eq!(
        templates[0].fields,
        [
            FieldSpecifier {
                information_element_id: 1,
                field_length: 4,
                enterprise_number: Some(9),
            },
            FieldSpecifier {
                information_element_id: OCTET_DELTA_COUNT,
                field_length: 4,
                enterprise_number: None,
            },
        ]
    );
    assert_eq!(
        data_set(&packet.sets[1]).records,
        [[Value::OctetArray(vec![0, 0, 0, 5]), Value::Unsigned32(6)]]
    );

    let mut registry = Registry::iana();
    registry.insert(InformationElement {
        id: 1,
        enterprise_number: Some(9),
        name: Cow::Borrowed("vendorCounter"),
        data_type: DataType::Unsigned32,
        semantics: Some(DataTypeSemantics::TotalCounter),
    });
    let packet = Parser::new(registry, Duration::from_mins(10))
        .parse(&datagram)
        .unwrap();
    assert_eq!(
        data_set(&packet.sets[1]).records,
        [[Value::Unsigned32(5), Value::Unsigned32(6)]]
    );
}

#[test]
fn variable_length_values_carry_their_length() {
    let template = set(
        TEMPLATE_SET_ID,
        &template(
            256,
            &[
                field(INTERFACE_NAME, VARIABLE_LENGTH),
                field(OCTET_DELTA_COUNT, 4),
            ],
        ),
    );
    let long_name = vec![b'a'; 300];
    let data = set(
        256,
        &[
            variable(b"eth0"),
            1u32.to_be_bytes().to_vec(),
            variable(&long_name),
            2u32.to_be_bytes().to_vec(),
            // The three-octet form for a short value.
            vec![255, 0, 3],
            b"abc".to_vec(),
            3u32.to_be_bytes().to_vec(),
        ]
        .concat(),
    );

    let packet = Parser::default()
        .parse(&message(DOMAIN, &[template, data]))
        .unwrap();
    let name = |name: &[u8]| Value::String(String::from_utf8(name.to_vec()).unwrap());
    assert_eq!(
        data_set(&packet.sets[1]).records,
        [
            [name(b"eth0"), Value::Unsigned32(1)],
            [name(&long_name), Value::Unsigned32(2)],
            [name(b"abc"), Value::Unsigned32(3)],
        ]
    );
}

#[test]
fn options_data_decodes_scope_values_before_option_values() {
    let template = set(
        OPTIONS_TEMPLATE_SET_ID,
        &options_template(
            257,
            1,
            &[field(OBSERVATION_DOMAIN_ID, 4), field(SAMPLING_INTERVAL, 4)],
        ),
    );
    let data = set(
        257,
        &[&DOMAIN.to_be_bytes()[..], &100u32.to_be_bytes()].concat(),
    );

    let packet = Parser::default()
        .parse(&message(DOMAIN, &[template, data]))
        .unwrap();

    let Set::OptionsTemplates(templates) = &packet.sets[0] else {
        panic!("expected an options template set");
    };
    let field = |id| FieldSpecifier {
        information_element_id: id,
        field_length: 4,
        enterprise_number: None,
    };
    assert_eq!(
        *templates[0],
        OptionsTemplate {
            template_id: 257,
            scope_fields: vec![field(OBSERVATION_DOMAIN_ID)],
            option_fields: vec![field(SAMPLING_INTERVAL)],
        }
    );
    let Set::OptionsData(data) = &packet.sets[1] else {
        panic!("expected an options data set");
    };
    assert!(Arc::ptr_eq(&templates[0], &data.template));
    assert_eq!(
        data.records,
        [[Value::Unsigned32(DOMAIN), Value::Unsigned32(100)]]
    );
}

#[test]
fn an_options_template_needs_one_to_all_of_its_fields_in_scope() {
    let fields = [field(OBSERVATION_DOMAIN_ID, 4), field(SAMPLING_INTERVAL, 4)];
    for scope_field_count in [0, 3] {
        let template = set(
            OPTIONS_TEMPLATE_SET_ID,
            &options_template(257, scope_field_count, &fields),
        );
        let packet = Parser::default()
            .parse(&message(DOMAIN, &[template, set(257, &[0; 8])]))
            .unwrap();
        assert_eq!(
            packet.sets,
            [Set::OptionsTemplates(Vec::new()), Set::Unknown(257)]
        );
    }
}

#[test]
fn withdrawals_are_parsed_but_not_applied() {
    let mut parser = Parser::default();
    parser
        .parse(&message(DOMAIN, &[octet_count_template()]))
        .unwrap();
    let withdrawals = set(
        TEMPLATE_SET_ID,
        &[template(256, &[]), template(TEMPLATE_SET_ID, &[])].concat(),
    );
    let options_withdrawals = set(
        OPTIONS_TEMPLATE_SET_ID,
        &[
            template(258, &[]),
            options_template(259, 1, &[field(OBSERVATION_DOMAIN_ID, 4)]),
        ]
        .concat(),
    );

    let packet = parser
        .parse(&message(
            DOMAIN,
            &[withdrawals, options_withdrawals, octet_count_data(42)],
        ))
        .unwrap();

    let Set::Templates(templates) = &packet.sets[0] else {
        panic!("expected a template set");
    };
    let withdrawn: Vec<_> = templates
        .iter()
        .map(|t| (t.template_id, t.fields.len()))
        .collect();
    assert_eq!(withdrawn, [(256, 0), (TEMPLATE_SET_ID, 0)]);
    let Set::OptionsTemplates(options_templates) = &packet.sets[1] else {
        panic!("expected an options template set");
    };
    assert_eq!(options_templates.len(), 2);
    assert!(options_templates[0].scope_fields.is_empty());
    assert_eq!(data_set(&packet.sets[2]).records, [[Value::Unsigned32(42)]]);
}

#[test]
fn reserved_template_ids_end_the_template_set() {
    let templates = set(
        TEMPLATE_SET_ID,
        &[
            template(255, &[field(OCTET_DELTA_COUNT, 4)]),
            template(256, &[field(OCTET_DELTA_COUNT, 4)]),
        ]
        .concat(),
    );
    let packet = Parser::default()
        .parse(&message(DOMAIN, &[templates, octet_count_data(1)]))
        .unwrap();
    assert_eq!(packet.sets, [Set::Templates(Vec::new()), Set::Unknown(256)]);
}

#[test]
fn padding_after_the_records_is_skipped() {
    let data = set(
        256,
        &[&1u32.to_be_bytes()[..], &2u32.to_be_bytes(), &[0; 3]].concat(),
    );
    let packet = Parser::default()
        .parse(&message(
            DOMAIN,
            &[octet_count_template(), data, octet_count_data(3)],
        ))
        .unwrap();
    assert_eq!(
        data_set(&packet.sets[1]).records,
        [[Value::Unsigned32(1)], [Value::Unsigned32(2)]]
    );
    assert_eq!(data_set(&packet.sets[2]).records, [[Value::Unsigned32(3)]]);
}

#[test]
fn templates_are_kept_per_domain_until_they_expire() {
    let mut parser = Parser::default();
    parser
        .parse(&message(DOMAIN, &[octet_count_template()]))
        .unwrap();
    let other_domain = parser.parse(&message(8, &[octet_count_data(1)])).unwrap();
    assert_eq!(other_domain.sets, [Set::Unknown(256)]);
    let same_domain = parser
        .parse(&message(DOMAIN, &[octet_count_data(1)]))
        .unwrap();
    assert!(matches!(same_domain.sets[0], Set::Data(_)));

    let mut expiring = Parser::new(Registry::iana(), Duration::ZERO);
    let packet = expiring
        .parse(&message(
            DOMAIN,
            &[octet_count_template(), octet_count_data(1)],
        ))
        .unwrap();
    assert_eq!(packet.sets[1], Set::Unknown(256));
}

#[test]
fn basic_lists_hold_values_of_one_element() {
    let template = set(
        TEMPLATE_SET_ID,
        &template(256, &[field(BASIC_LIST, VARIABLE_LENGTH)]),
    );
    let list = [
        vec![3],
        field(INTERFACE_NAME, VARIABLE_LENGTH),
        variable(b"abc"),
        variable(b""),
        variable(b"def"),
    ]
    .concat();
    let data = set(256, &variable(&list));

    let packet = Parser::default()
        .parse(&message(DOMAIN, &[template, data]))
        .unwrap();

    let name = |name: &str| Value::String(name.to_owned());
    assert_eq!(
        *only_value(&packet),
        Value::BasicList(Box::new(BasicList {
            semantic: ListSemantic::AllOf,
            field: FieldSpecifier {
                information_element_id: INTERFACE_NAME,
                field_length: VARIABLE_LENGTH,
                enterprise_number: None,
            },
            values: vec![name("abc"), name(""), name("def")],
        }))
    );
}

#[test]
fn a_basic_list_of_zero_length_elements_ends() {
    let template = set(
        TEMPLATE_SET_ID,
        &template(256, &[field(BASIC_LIST, VARIABLE_LENGTH)]),
    );
    let list = [vec![255], field(OCTET_DELTA_COUNT, 0), vec![1, 2]].concat();
    let data = set(256, &variable(&list));

    let packet = Parser::default()
        .parse(&message(DOMAIN, &[template, data]))
        .unwrap();

    let Value::BasicList(list) = only_value(&packet) else {
        panic!("expected a basic list");
    };
    assert!(list.values.is_empty());
}

#[test]
fn sub_template_lists_hold_records_of_one_template() {
    let templates = set(
        TEMPLATE_SET_ID,
        &[
            template(256, &[field(OCTET_DELTA_COUNT, 4)]),
            template(257, &[field(SUB_TEMPLATE_LIST, VARIABLE_LENGTH)]),
        ]
        .concat(),
    );
    let known = [
        &[255][..],
        &256u16.to_be_bytes(),
        &1u32.to_be_bytes(),
        &2u32.to_be_bytes(),
    ]
    .concat();
    let unknown = [&[255][..], &300u16.to_be_bytes(), &[9, 9]].concat();
    let data = set(257, &[variable(&known), variable(&unknown)].concat());

    let packet = Parser::default()
        .parse(&message(DOMAIN, &[templates, data]))
        .unwrap();

    let Set::Templates(templates) = &packet.sets[0] else {
        panic!("expected a template set");
    };
    let records = &data_set(&packet.sets[1]).records;
    assert_eq!(
        records[0][0],
        Value::SubTemplateList(Box::new(SubTemplateList {
            semantic: ListSemantic::Undefined,
            records: ListRecords::Decoded {
                template: TemplateRef::Data(Arc::clone(&templates[0])),
                records: vec![vec![Value::Unsigned32(1)], vec![Value::Unsigned32(2)]],
            },
        }))
    );
    assert_eq!(
        records[1][0],
        Value::SubTemplateList(Box::new(SubTemplateList {
            semantic: ListSemantic::Undefined,
            records: ListRecords::Undecoded {
                template_id: 300,
                data: vec![9, 9],
            },
        }))
    );
}

#[test]
fn sub_template_multi_lists_hold_groups_of_records() {
    let templates = set(
        TEMPLATE_SET_ID,
        &[
            template(256, &[field(OCTET_DELTA_COUNT, 4)]),
            template(257, &[field(SUB_TEMPLATE_MULTI_LIST, VARIABLE_LENGTH)]),
        ]
        .concat(),
    );
    let group = |template_id: u16, records: &[u8]| {
        let length = u16::try_from(LIST_GROUP_HEADER_SIZE + records.len()).unwrap();
        [
            &template_id.to_be_bytes()[..],
            &length.to_be_bytes(),
            records,
        ]
        .concat()
    };
    let list = [
        vec![1],
        group(256, &1u32.to_be_bytes()),
        group(300, &[9, 9]),
        group(256, &[]),
    ]
    .concat();
    let data = set(257, &variable(&list));

    let packet = Parser::default()
        .parse(&message(DOMAIN, &[templates, data]))
        .unwrap();

    let Set::Templates(templates) = &packet.sets[0] else {
        panic!("expected a template set");
    };
    let octet_counts = |records| ListRecords::Decoded {
        template: TemplateRef::Data(Arc::clone(&templates[0])),
        records,
    };
    assert_eq!(
        *only_value(&packet),
        Value::SubTemplateMultiList(Box::new(SubTemplateMultiList {
            semantic: ListSemantic::ExactlyOneOf,
            groups: vec![
                octet_counts(vec![vec![Value::Unsigned32(1)]]),
                ListRecords::Undecoded {
                    template_id: 300,
                    data: vec![9, 9],
                },
                octet_counts(Vec::new()),
            ],
        }))
    );
}

#[test]
fn lists_nested_too_deep_keep_their_bytes() {
    let template = set(
        TEMPLATE_SET_ID,
        &template(256, &[field(BASIC_LIST, VARIABLE_LENGTH)]),
    );
    let mut list = [
        vec![255],
        field(OCTET_DELTA_COUNT, 4),
        5u32.to_be_bytes().to_vec(),
    ]
    .concat();
    for _ in 0..MAX_LIST_DEPTH + 2 {
        list = [
            vec![255],
            field(BASIC_LIST, VARIABLE_LENGTH),
            variable(&list),
        ]
        .concat();
    }
    let data = set(256, &variable(&list));

    let packet = Parser::default()
        .parse(&message(DOMAIN, &[template, data]))
        .unwrap();

    let mut value = only_value(&packet);
    let mut depth = 0;
    while let Value::BasicList(list) = value {
        depth += 1;
        value = &list.values[0];
    }
    assert_eq!(depth, MAX_LIST_DEPTH);
    assert!(matches!(value, Value::OctetArray(_)));
}

fn type_template() -> Vec<u8> {
    set(
        OPTIONS_TEMPLATE_SET_ID,
        &options_template(
            TYPE_TEMPLATE_ID,
            2,
            &[
                field(INFORMATION_ELEMENT_ID, 2),
                field(PRIVATE_ENTERPRISE_NUMBER, 4),
                field(INFORMATION_ELEMENT_DATA_TYPE, 1),
                field(INFORMATION_ELEMENT_SEMANTICS, 1),
                field(INFORMATION_ELEMENT_NAME, VARIABLE_LENGTH),
            ],
        ),
    )
}

fn type_record(
    id: u16,
    enterprise_number: u32,
    data_type: DataType,
    semantics: DataTypeSemantics,
    name: &[u8],
) -> Vec<u8> {
    [
        &id.to_be_bytes()[..],
        &enterprise_number.to_be_bytes(),
        &[data_type as u8, semantics as u8],
        &variable(name),
    ]
    .concat()
}

/// Describes the vendor's element 1 as an unsigned32 counter.
fn vendor_counter_type() -> Vec<u8> {
    type_record(
        1,
        VENDOR_ENTERPRISE_NUMBER,
        DataType::Unsigned32,
        DataTypeSemantics::TotalCounter,
        b"vendorCounter",
    )
}

fn type_records(records: &[Vec<u8>]) -> Vec<u8> {
    set(TYPE_TEMPLATE_ID, &records.concat())
}

fn vendor_template() -> Vec<u8> {
    set(
        TEMPLATE_SET_ID,
        &template(256, &[enterprise_field(1, 4, VENDOR_ENTERPRISE_NUMBER)]),
    )
}

fn vendor_data() -> Vec<u8> {
    set(256, &5u32.to_be_bytes())
}

#[test]
fn type_records_describe_elements_for_the_data_after_them() {
    let mut parser = Parser::default();
    let packet = parser
        .parse(&message(
            DOMAIN,
            &[
                type_template(),
                type_records(&[vendor_counter_type()]),
                vendor_template(),
                vendor_data(),
            ],
        ))
        .unwrap();

    assert_eq!(*only_value(&packet), Value::Unsigned32(5));
    assert_eq!(
        parser.element(DOMAIN, &VENDOR_FIELD),
        Some(&InformationElement {
            id: 1,
            enterprise_number: Some(VENDOR_ENTERPRISE_NUMBER),
            name: Cow::Borrowed("vendorCounter"),
            data_type: DataType::Unsigned32,
            semantics: Some(DataTypeSemantics::TotalCounter),
        })
    );
}

#[test]
fn templates_received_before_a_type_record_decode_by_it() {
    let mut parser = Parser::default();
    let before = parser
        .parse(&message(DOMAIN, &[vendor_template(), vendor_data()]))
        .unwrap();
    assert_eq!(*only_value(&before), Value::OctetArray(vec![0, 0, 0, 5]));

    let after = parser
        .parse(&message(
            DOMAIN,
            &[
                type_template(),
                type_records(&[vendor_counter_type()]),
                vendor_data(),
            ],
        ))
        .unwrap();
    assert_eq!(*only_value(&after), Value::Unsigned32(5));
}

#[test]
fn type_records_never_redefine_a_known_element() {
    let as_string = type_record(
        OCTET_DELTA_COUNT,
        0,
        DataType::String,
        DataTypeSemantics::Default,
        b"octets",
    );
    let packet = Parser::default()
        .parse(&message(
            DOMAIN,
            &[
                type_template(),
                type_records(&[as_string]),
                octet_count_template(),
                octet_count_data(5),
            ],
        ))
        .unwrap();
    assert_eq!(*only_value(&packet), Value::Unsigned32(5));
}

#[test]
fn an_element_whose_type_records_disagree_is_ignored() {
    let as_string = type_record(
        1,
        VENDOR_ENTERPRISE_NUMBER,
        DataType::String,
        DataTypeSemantics::Default,
        b"vendorCounter",
    );
    let mut parser = Parser::default();
    let packet = parser
        .parse(&message(
            DOMAIN,
            &[
                type_template(),
                type_records(&[vendor_counter_type(), vendor_counter_type()]),
                type_records(&[as_string]),
                vendor_template(),
                vendor_data(),
            ],
        ))
        .unwrap();

    assert_eq!(*only_value(&packet), Value::OctetArray(vec![0, 0, 0, 5]));
    assert_eq!(parser.element(DOMAIN, &VENDOR_FIELD), None);
}

#[test]
fn semantics_that_do_not_fit_the_data_type_are_ignored() {
    let string_counter = type_record(
        1,
        VENDOR_ENTERPRISE_NUMBER,
        DataType::String,
        DataTypeSemantics::DeltaCounter,
        b"vendorName",
    );
    let mut parser = Parser::default();
    parser
        .parse(&message(
            DOMAIN,
            &[type_template(), type_records(&[string_counter])],
        ))
        .unwrap();
    assert_eq!(parser.element(DOMAIN, &VENDOR_FIELD), None);
}

#[test]
fn described_elements_belong_to_their_observation_domain() {
    let mut parser = Parser::default();
    parser
        .parse(&message(
            DOMAIN,
            &[type_template(), type_records(&[vendor_counter_type()])],
        ))
        .unwrap();
    let other_domain = parser
        .parse(&message(8, &[vendor_template(), vendor_data()]))
        .unwrap();
    assert_eq!(
        *only_value(&other_domain),
        Value::OctetArray(vec![0, 0, 0, 5])
    );
}

#[test]
fn the_enterprise_bit_of_a_described_id_is_ignored() {
    let with_bit = type_record(
        1 | ENTERPRISE_BIT,
        VENDOR_ENTERPRISE_NUMBER,
        DataType::Unsigned32,
        DataTypeSemantics::Quantity,
        b"",
    );
    let mut parser = Parser::default();
    parser
        .parse(&message(
            DOMAIN,
            &[type_template(), type_records(&[with_bit])],
        ))
        .unwrap();
    assert_eq!(parser.element(DOMAIN, &VENDOR_FIELD).map(|e| e.id), Some(1));
}

#[test]
fn an_unusable_name_is_replaced_by_the_element_key() {
    let records = [b"bad\0name".as_slice(), b""].map(|name| {
        type_record(
            1,
            VENDOR_ENTERPRISE_NUMBER,
            DataType::Unsigned32,
            DataTypeSemantics::Quantity,
            name,
        )
    });
    for record in records {
        let mut parser = Parser::default();
        parser
            .parse(&message(
                DOMAIN,
                &[type_template(), type_records(&[record])],
            ))
            .unwrap();
        let name = &parser.element(DOMAIN, &VENDOR_FIELD).unwrap().name;
        assert_eq!(name, "9.1");
    }
}

#[test]
fn a_type_record_has_the_element_id_in_scope() {
    let not_in_scope = set(
        OPTIONS_TEMPLATE_SET_ID,
        &options_template(
            TYPE_TEMPLATE_ID,
            1,
            &[
                field(OBSERVATION_DOMAIN_ID, 4),
                field(INFORMATION_ELEMENT_ID, 2),
                field(PRIVATE_ENTERPRISE_NUMBER, 4),
                field(INFORMATION_ELEMENT_DATA_TYPE, 1),
            ],
        ),
    );
    let record = [
        &DOMAIN.to_be_bytes()[..],
        &1u16.to_be_bytes(),
        &VENDOR_ENTERPRISE_NUMBER.to_be_bytes(),
        &[DataType::Unsigned32 as u8],
    ]
    .concat();
    let mut parser = Parser::default();
    parser
        .parse(&message(DOMAIN, &[not_in_scope, type_records(&[record])]))
        .unwrap();
    assert_eq!(parser.element(DOMAIN, &VENDOR_FIELD), None);
}

#[test]
fn list_semantics_follow_the_iana_registry() {
    let semantics: Vec<_> = [0, 1, 2, 3, 4, 5, 255].map(ListSemantic::from).into();
    assert_eq!(
        semantics,
        [
            ListSemantic::NoneOf,
            ListSemantic::ExactlyOneOf,
            ListSemantic::OneOrMoreOf,
            ListSemantic::AllOf,
            ListSemantic::Ordered,
            ListSemantic::Unassigned(5),
            ListSemantic::Undefined,
        ]
    );
    for number in 0..=u8::MAX {
        assert_eq!(u8::from(ListSemantic::from(number)), number);
    }
}

#[cfg(feature = "serde")]
#[test]
fn round_trips_through_serde() {
    let template = set(
        TEMPLATE_SET_ID,
        &template(256, &[field(BASIC_LIST, VARIABLE_LENGTH)]),
    );
    let list = [
        vec![4],
        field(OCTET_DELTA_COUNT, 4),
        7u32.to_be_bytes().to_vec(),
    ]
    .concat();
    let packet = Parser::default()
        .parse(&message(DOMAIN, &[template, set(256, &variable(&list))]))
        .unwrap();
    let json = serde_json::to_value(&packet).unwrap();
    assert_eq!(json["observation_domain_id"], DOMAIN);
    assert_eq!(serde_json::from_value::<Packet>(json).unwrap(), packet);
}
