use std::fmt::{self, Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use nom::bytes::complete::take;
use nom::combinator::{cond, map, map_parser, verify};
use nom::multi::{count, many0};
use nom::number::complete::{
    be_f32, be_f64, be_i8, be_i16, be_i32, be_i64, be_u8, be_u16, be_u32, be_u64,
};
use nom::{IResult, Parser, ToUsize};
use primitive_types::U256;
use serde::Serialize;
use strum::EnumString;

use crate::common::ie_registry::{DataType, IERegistry};
use crate::common::parser::{
    ipv4_addr, ipv6_addr, macaddr6, string, timestamp_micros, timestamp_millis, timestamp_nanos,
    timestamp_secs, vector,
};
use crate::common::serializer::serialize_as_hex;
use crate::common::timeout_map::TimeoutHashMap;

pub const IPFIX_VERSION: u16 = 10;
pub const IPFIX_TEMPLATE_SET_ID: u16 = 2;
pub const IPFIX_OPTIONS_TEMPLATE_SET_ID: u16 = 3;
pub const IPFIX_VALID_TEMPLATE_ID: RangeInclusive<u16> = 256..=65535;
pub const IPFIX_VARIABLE_LENGTH: u16 = 0xffff;

/// Set header size: 2 (set_id) + 2 (length)
pub const SET_HEADER_SIZE: usize = 4;

/// IPFIX header size: 2 (version) + 2 (length) + 4 (export_time) + 4
/// (sequence_number) + 4 (observation_domain_id)
pub const IPFIX_HEADER_SIZE: usize = 16;

// (observation_domain_id, template_id)
type TemplateKey = (u32, u16);

pub struct IpfixParser {
    pub ie_registry: IERegistry,
    pub templates: TimeoutHashMap<TemplateKey, CachedTemplate<TemplateRecord>>,
    pub options_templates: TimeoutHashMap<TemplateKey, CachedTemplate<OptionsTemplateRecord>>,
}

impl IpfixParser {
    pub fn new(ie_registry: IERegistry, timeout: std::time::Duration) -> Self {
        Self {
            ie_registry,
            templates: TimeoutHashMap::new(timeout),
            options_templates: TimeoutHashMap::new(timeout),
        }
    }

    pub fn parse<'a>(&mut self, input: &'a [u8]) -> IResult<&'a [u8], IpfixPacket> {
        let (input, header) = parse_header(input)?;
        let data_length = (header.length as usize).saturating_sub(IPFIX_HEADER_SIZE);
        let (input, sets) = map_parser(take(data_length), |data| {
            many0(|i| self.parse_set(header.observation_domain_id, i)).parse(data)
        })
        .parse(input)?;

        Ok((input, IpfixPacket { header, sets }))
    }

    fn lookup_field_info(&self, field: &FieldSpecifier) -> (DataType, Arc<str>) {
        self.ie_registry
            .lookup(
                field.information_element_identifier,
                field.enterprise_number,
            )
            .map_or_else(
                || {
                    (
                        DataType::OctetArray,
                        Arc::from(field.information_element_identifier.to_string()),
                    )
                },
                |ie| (ie.data_type, ie.name.clone()),
            )
    }

    /// Resolve a template's field list against the IE registry once.
    ///
    /// The answer is fixed for the life of the template, but was previously
    /// recomputed for every data record: a hash lookup and an `Arc` clone per
    /// field, ~300 per packet on a typical 20-record IPFIX packet, which
    /// profiled as the single hottest function in the collector. Scope fields
    /// additionally formatted their identifier into a fresh `String` each
    /// time. Doing it at template-install time turns record parsing into an
    /// indexed walk.
    fn resolve_fields(&self, fields: &[FieldSpecifier], scope_count: usize) -> Vec<ResolvedField> {
        fields
            .iter()
            .enumerate()
            .map(|(idx, field)| {
                // Scope fields are not registry elements; they keep the
                // identifier as their name, as before.
                let (data_type, name) = if idx < scope_count {
                    (
                        DataType::Unsigned,
                        Arc::from(field.information_element_identifier.to_string()),
                    )
                } else {
                    self.lookup_field_info(field)
                };
                ResolvedField {
                    spec: field.clone(),
                    data_type,
                    name,
                }
            })
            .collect()
    }

    fn parse_templated_records<'a>(
        &self,
        observation_domain_id: u32,
        template_id: u16,
        input: &'a [u8],
    ) -> IResult<&'a [u8], Vec<Record>> {
        let key = (observation_domain_id, template_id);

        if let Some(t) = self.templates.get(&key) {
            let (input, records) =
                many0(|i| self.parse_record_from_fields(observation_domain_id, &t.fields, i))
                    .parse(input)?;
            return Ok((input, records.into_iter().map(Record::Data).collect()));
        }

        if let Some(t) = self.options_templates.get(&key) {
            let (input, records) =
                many0(|i| self.parse_record_from_fields(observation_domain_id, &t.fields, i))
                    .parse(input)?;
            return Ok((
                input,
                records.into_iter().map(Record::OptionsData).collect(),
            ));
        }

        Ok((input, vec![]))
    }

    fn parse_set<'a>(
        &mut self,
        observation_domain_id: u32,
        input: &'a [u8],
    ) -> IResult<&'a [u8], Set> {
        let (input, id) = be_u16(input)?;
        let (input, length) = be_u16(input)?;

        let value_length = (length as usize).saturating_sub(SET_HEADER_SIZE);
        let (input, records) = map_parser(take(value_length), |data| {
            self.parse_records(observation_domain_id, id, data)
        })
        .parse(input)?;

        Ok((
            input,
            Set {
                id,
                length,
                records,
            },
        ))
    }

    fn parse_records<'a>(
        &mut self,
        observation_domain_id: u32,
        set_id: u16,
        input: &'a [u8],
    ) -> IResult<&'a [u8], Vec<Record>> {
        match set_id {
            IPFIX_TEMPLATE_SET_ID => {
                let (input, templates) = many0(parse_template_record).parse(input)?;

                for template in &templates {
                    let fields = self.resolve_fields(&template.fields, 0);
                    self.templates.insert(
                        (observation_domain_id, template.template_id),
                        CachedTemplate {
                            record: template.clone(),
                            fields,
                        },
                    );
                }

                Ok((input, templates.into_iter().map(Record::Template).collect()))
            }
            IPFIX_OPTIONS_TEMPLATE_SET_ID => {
                let (input, options_templates) =
                    many0(parse_options_template_record).parse(input)?;

                for template in &options_templates {
                    let fields = self
                        .resolve_fields(&template.fields, template.scope_field_count as usize);
                    self.options_templates.insert(
                        (observation_domain_id, template.template_id),
                        CachedTemplate {
                            record: template.clone(),
                            fields,
                        },
                    );
                }

                Ok((
                    input,
                    options_templates
                        .into_iter()
                        .map(Record::OptionsTemplate)
                        .collect(),
                ))
            }
            template_id if IPFIX_VALID_TEMPLATE_ID.contains(&template_id) => {
                let (remaining, records) =
                    self.parse_templated_records(observation_domain_id, template_id, input)?;

                if records.is_empty() && !input.is_empty() {
                    log::warn!(
                        "Unknown template for observation_domain_id: {}, template_id: {}",
                        observation_domain_id,
                        template_id
                    );
                }

                Ok((remaining, records))
            }
            _ => {
                log::warn!("Invalid set ID: {}. Skipping.", set_id);

                Ok((input, vec![]))
            }
        }
    }

    fn parse_record_from_fields<'a>(
        &self,
        observation_domain_id: u32,
        fields: &[ResolvedField],
        input: &'a [u8],
    ) -> IResult<&'a [u8], DataRecord> {
        let mut values = Vec::with_capacity(fields.len());
        let mut remaining = input;

        for field in fields {
            let (input, field_length) = parse_field_length(field.spec.field_length, remaining)?;
            let (input, value) =
                self.parse_field_value(observation_domain_id, field.data_type, field_length, input)?;
            values.push((
                field.spec.enterprise_number,
                field.spec.information_element_identifier,
                Arc::clone(&field.name),
                value,
            ));
            remaining = input;
        }

        Ok((remaining, DataRecord(values)))
    }

    fn parse_field_value<'a>(
        &self,
        observation_domain_id: u32,
        data_type: DataType,
        length: usize,
        input: &'a [u8],
    ) -> IResult<&'a [u8], FieldValue> {
        match (data_type, length) {
            (DataType::Boolean, 1) => map(boolean, FieldValue::Boolean).parse(input),
            (DataType::Unsigned, 1) => map(be_u8, FieldValue::Unsigned8).parse(input),
            (DataType::Unsigned, 2) => map(be_u16, FieldValue::Unsigned16).parse(input),
            (DataType::Unsigned, 4) => map(be_u32, FieldValue::Unsigned32).parse(input),
            (DataType::Unsigned, 8) => map(be_u64, FieldValue::Unsigned64).parse(input),
            (DataType::Signed, 1) => map(be_i8, FieldValue::Signed8).parse(input),
            (DataType::Signed, 2) => map(be_i16, FieldValue::Signed16).parse(input),
            (DataType::Signed, 4) => map(be_i32, FieldValue::Signed32).parse(input),
            (DataType::Signed, 8) => map(be_i64, FieldValue::Signed64).parse(input),
            (DataType::Float, 4) => map(be_f32, FieldValue::Float32).parse(input),
            (DataType::Float, 8) => map(be_f64, FieldValue::Float64).parse(input),
            (DataType::MacAddress, 6) => map(macaddr6, FieldValue::MacAddress).parse(input),
            (DataType::Ipv4Address, 4) => map(ipv4_addr, FieldValue::Ipv4Address).parse(input),
            (DataType::Ipv6Address, 16) => map(ipv6_addr, FieldValue::Ipv6Address).parse(input),
            (DataType::String, len) => map(string(len), FieldValue::String).parse(input),
            (DataType::DateTimeSeconds, 4) => {
                map(timestamp_secs, FieldValue::DateTimeSeconds).parse(input)
            }
            (DataType::DateTimeMilliseconds, 8) => {
                map(timestamp_millis, FieldValue::DateTimeMilliseconds).parse(input)
            }
            (DataType::DateTimeMicroseconds, 8) => {
                map(timestamp_micros, FieldValue::DateTimeMicroseconds).parse(input)
            }
            (DataType::DateTimeNanoseconds, 8) => {
                map(timestamp_nanos, FieldValue::DateTimeNanoseconds).parse(input)
            }
            (DataType::BasicList, len) => self.parse_basic_list(observation_domain_id, len, input),
            (DataType::SubTemplateList, len) => {
                self.parse_sub_template_list(observation_domain_id, len, input)
            }
            (DataType::SubTemplateMultiList, len) => {
                self.parse_sub_template_multi_list(observation_domain_id, len, input)
            }
            _ => map(vector(length), FieldValue::OctetArray).parse(input),
        }
    }

    fn parse_basic_list<'a>(
        &self,
        observation_domain_id: u32,
        length: usize,
        input: &'a [u8],
    ) -> IResult<&'a [u8], FieldValue> {
        let (remaining, data) = take(length)(input)?;
        let (data, semantic) = map(be_u8, Semantic::from).parse(data)?;
        let (data, field) = parse_field_specifier(data)?;

        let (element_data_type, _) = self.lookup_field_info(&field);
        let mut content = Vec::new();
        let mut list_data = data;

        while !list_data.is_empty() {
            let (next_data, actual_length) = parse_field_length(field.field_length, list_data)?;
            if actual_length == 0 || next_data.len() < actual_length {
                break;
            }

            let (next_data, value) = self.parse_field_value(
                observation_domain_id,
                element_data_type,
                actual_length,
                next_data,
            )?;
            content.push(value);
            list_data = next_data;
        }

        Ok((
            remaining,
            FieldValue::BasicList(BasicList {
                semantic,
                field,
                content,
            }),
        ))
    }

    fn parse_sub_template_list<'a>(
        &self,
        observation_domain_id: u32,
        length: usize,
        input: &'a [u8],
    ) -> IResult<&'a [u8], FieldValue> {
        let (remaining, data) = take(length)(input)?;
        let (data, semantic) = map(be_u8, Semantic::from).parse(data)?;
        let (data, template_id) = be_u16(data)?;

        let (_, records) =
            self.parse_templated_records(observation_domain_id, template_id, data)?;

        if records.is_empty() && !data.is_empty() {
            log::warn!(
                "SubTemplateList references unknown template_id: {} for observation_domain_id: {}",
                template_id,
                observation_domain_id
            );
        }

        let data_records: Vec<DataRecord> = records
            .into_iter()
            .filter_map(|r| match r {
                Record::Data(dr) | Record::OptionsData(dr) => Some(dr),
                _ => None,
            })
            .collect();

        Ok((
            remaining,
            FieldValue::SubTemplateList(SubTemplateList {
                semantic,
                template_id,
                data: data_records,
            }),
        ))
    }

    fn parse_sub_template_multi_list<'a>(
        &self,
        observation_domain_id: u32,
        length: usize,
        input: &'a [u8],
    ) -> IResult<&'a [u8], FieldValue> {
        let (remaining, data) = take(length)(input)?;
        let (data, semantic) = map(be_u8, Semantic::from).parse(data)?;

        let mut items = Vec::new();
        let mut list_data = data;

        while !list_data.is_empty() {
            let (next_data, template_id) = be_u16(list_data)?;
            let (next_data, item_length) = be_u16(next_data)?;
            let content_length = (item_length as usize).saturating_sub(4);

            if content_length == 0 {
                list_data = next_data;
                continue;
            }

            let (next_data, item_data) = take(content_length)(next_data)?;
            let (_, records) =
                self.parse_templated_records(observation_domain_id, template_id, item_data)?;

            if records.is_empty() && !item_data.is_empty() {
                log::warn!(
                    "SubTemplateMultiList item references unknown template_id: {} for observation_domain_id: {}",
                    template_id,
                    observation_domain_id
                );
            }

            let data_records: Vec<DataRecord> = records
                .into_iter()
                .filter_map(|r| match r {
                    Record::Data(dr) | Record::OptionsData(dr) => Some(dr),
                    _ => None,
                })
                .collect();

            items.push(SubTemplateMultiItem {
                template_id,
                length: item_length,
                data: data_records,
            });
            list_data = next_data;
        }

        Ok((
            remaining,
            FieldValue::SubTemplateMultiList(SubTemplateMultiList {
                semantic,
                data: items,
            }),
        ))
    }
}

impl Default for IpfixParser {
    fn default() -> Self {
        let ie_registry = IERegistry::default();
        let timeout = std::time::Duration::from_mins(10);

        Self {
            ie_registry,
            templates: TimeoutHashMap::new(timeout),
            options_templates: TimeoutHashMap::new(timeout),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IpfixPacket {
    #[serde(flatten)]
    pub header: Header,
    pub sets: Vec<Set>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub version: u16,
    pub length: u16,
    pub export_time: DateTime<Utc>,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, export_time) = timestamp_secs(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, observation_domain_id) = be_u32(input)?;

    Ok((
        input,
        Header {
            version,
            length,
            export_time,
            sequence_number,
            observation_domain_id,
        },
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct Set {
    pub id: u16,
    pub length: u16,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone)]
pub struct SetHeader {
    pub set_id: u16,
    pub length: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Record {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data(DataRecord),
    OptionsData(DataRecord),
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

fn parse_template_record(input: &[u8]) -> IResult<&[u8], TemplateRecord> {
    let (input, template_id) =
        verify(be_u16, |i| IPFIX_VALID_TEMPLATE_ID.contains(i)).parse(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, fields) = count(parse_field_specifier, field_count.to_usize()).parse(input)?;

    Ok((
        input,
        TemplateRecord {
            template_id,
            field_count,
            fields,
        },
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

fn parse_options_template_record(input: &[u8]) -> IResult<&[u8], OptionsTemplateRecord> {
    let (input, template_id) =
        verify(be_u16, |i| IPFIX_VALID_TEMPLATE_ID.contains(i)).parse(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, scope_field_count) = be_u16(input)?;
    let (input, fields) = count(parse_field_specifier, field_count.to_usize()).parse(input)?;

    Ok((
        input,
        OptionsTemplateRecord {
            template_id,
            field_count,
            scope_field_count,
            fields,
        },
    ))
}

/// One template field with its registry metadata already resolved.
#[derive(Debug, Clone)]
pub struct ResolvedField {
    pub spec: FieldSpecifier,
    pub data_type: DataType,
    pub name: Arc<str>,
}

/// A cached template: the record exactly as it arrived, plus its fields
/// resolved against the IE registry.
///
/// Both are stored together so a re-sent template that changes its fields
/// cannot leave stale metadata behind — the whole entry is replaced.
#[derive(Debug, Clone)]
pub struct CachedTemplate<T> {
    pub record: T,
    pub fields: Vec<ResolvedField>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldSpecifier {
    pub enterprise_bit: bool,
    pub information_element_identifier: u16,
    pub field_length: u16,
    pub enterprise_number: Option<u32>,
}

fn parse_field_specifier(input: &[u8]) -> IResult<&[u8], FieldSpecifier> {
    let (input, enterprise_bit_and_information_element_identifier) = be_u16(input)?;

    let enterprise_bit = enterprise_bit_and_information_element_identifier & 0x8000 != 0;
    let information_element_identifier = enterprise_bit_and_information_element_identifier & 0x7fff;

    let (input, field_length) = be_u16(input)?;
    let (input, enterprise_number) = cond(enterprise_bit, be_u32).parse(input)?;

    Ok((
        input,
        FieldSpecifier {
            enterprise_bit,
            information_element_identifier,
            field_length,
            enterprise_number,
        },
    ))
}

#[derive(Debug, Clone)]
pub struct DataRecord(pub Vec<(Option<u32>, u16, Arc<str>, FieldValue)>);

impl Serialize for DataRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (_, _, key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }

        map.end()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    Unsigned256(U256),
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    Float32(f32),
    Float64(f64),
    Boolean(bool),
    MacAddress(MacAddr6),
    #[serde(serialize_with = "serialize_as_hex")]
    OctetArray(Vec<u8>),
    String(String),
    DateTimeSeconds(DateTime<Utc>),
    DateTimeMilliseconds(DateTime<Utc>),
    DateTimeMicroseconds(DateTime<Utc>),
    DateTimeNanoseconds(DateTime<Utc>),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
    BasicList(BasicList),
    SubTemplateList(SubTemplateList),
    SubTemplateMultiList(SubTemplateMultiList),
}

impl Display for FieldValue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            // According to RFC 7373
            FieldValue::Unsigned8(v) => write!(f, "{}", v),
            FieldValue::Unsigned16(v) => write!(f, "{}", v),
            FieldValue::Unsigned32(v) => write!(f, "{}", v),
            FieldValue::Unsigned64(v) => write!(f, "{}", v),
            FieldValue::Unsigned256(v) => write!(f, "{}", v),
            FieldValue::Signed8(v) => write!(f, "{}", v),
            FieldValue::Signed16(v) => write!(f, "{}", v),
            FieldValue::Signed32(v) => write!(f, "{}", v),
            FieldValue::Signed64(v) => write!(f, "{}", v),
            FieldValue::Float32(v) => write!(f, "{}", v),
            FieldValue::Float64(v) => write!(f, "{}", v),
            FieldValue::Boolean(v) => write!(f, "{}", v),
            FieldValue::MacAddress(v) => write!(f, "{}", v),
            FieldValue::OctetArray(v) => write!(f, "{}", hex::encode(v)),
            FieldValue::String(v) => write!(f, "{}", v),
            FieldValue::DateTimeSeconds(v) => write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S")),
            FieldValue::DateTimeMilliseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%3f"))
            }
            FieldValue::DateTimeMicroseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%6f"))
            }
            FieldValue::DateTimeNanoseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%9f"))
            }
            FieldValue::Ipv4Address(v) => write!(f, "{}", v),
            FieldValue::Ipv6Address(v) => write!(f, "{}", v),
            // There is no RFC for these
            FieldValue::BasicList(v) => write!(f, "{:?}", v),
            FieldValue::SubTemplateList(v) => write!(f, "{:?}", v),
            FieldValue::SubTemplateMultiList(v) => write!(f, "{:?}", v),
        }
    }
}

#[derive(Debug, Clone, Serialize, EnumString)]
#[strum(serialize_all = "camelCase")]
#[repr(u8)]
pub enum Semantic {
    NoneOf = 0x00,
    ExactlyOneOf = 0x01,
    OneOrMoreOf = 0x02,
    AllOf = 0x03,
    Ordered = 0x04,
    Undefined = 0xff,
}

impl From<u8> for Semantic {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Semantic::NoneOf,
            0x01 => Semantic::ExactlyOneOf,
            0x02 => Semantic::OneOrMoreOf,
            0x03 => Semantic::AllOf,
            0x04 => Semantic::Ordered,
            _ => Semantic::Undefined,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicList {
    pub semantic: Semantic,
    pub field: FieldSpecifier,
    pub content: Vec<FieldValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateList {
    pub semantic: Semantic,
    pub template_id: u16,
    pub data: Vec<DataRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateMultiList {
    pub semantic: Semantic,
    pub data: Vec<SubTemplateMultiItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubTemplateMultiItem {
    pub template_id: u16,
    pub length: u16,
    pub data: Vec<DataRecord>,
}

// 1 for true, 2 for false according to https://datatracker.ietf.org/doc/html/rfc7011#section-6.1.5
fn boolean(input: &[u8]) -> IResult<&[u8], bool> {
    map(verify(be_u8, |v| *v == 1 || *v == 2), |v| v == 1).parse(input)
}

fn parse_field_length(field_length: u16, input: &[u8]) -> IResult<&[u8], usize> {
    if field_length != IPFIX_VARIABLE_LENGTH {
        return Ok((input, field_length as usize));
    }

    let (input, first_byte) = be_u8(input)?;

    if first_byte < 255 {
        Ok((input, first_byte as usize))
    } else {
        map(be_u16, |l| l as usize).parse(input)
    }
}
