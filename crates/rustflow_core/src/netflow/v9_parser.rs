use nom::bytes::complete::take;
use nom::combinator::{fail, verify};
use nom::error::Error;
use nom::multi::{many, many0, many1};
use nom::number::complete::{be_u16, be_u32};
use nom::{IResult, Parser, ToUsize};
use rustc_hash::FxHashMap;
use serde::Serialize;

pub const NETFLOW_V9_VERSION: u16 = 9;

/// FlowSet ID value of 0 is reserved for the Template FlowSet.
pub const TEMPLATE_FLOW_SET_ID: u16 = 0;

/// FlowSet ID value of 1 is reserved for the Options Template.
pub const OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

/// Template IDs of Data FlowSets are numbered from 256 to 65,535.
pub const DATA_FLOW_SET_ID_RANGE: std::ops::RangeInclusive<u16> = 256..=65535;

pub type SourceId = u32;
pub type TemplateId = u16;

pub type TemplateKey = (SourceId, TemplateId);

#[derive(Debug, Clone, Serialize)]
pub enum TemplateValue {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
}

pub type TemplatesMap = FxHashMap<TemplateKey, TemplateValue>;

#[repr(u16)]
#[derive(Debug, Clone, Copy, Serialize, Eq, Hash, PartialEq)]
pub enum FieldType {
    InBytes = 1,
    InPkts = 2,
    Flows = 3,
    Protocol = 4,
    Tos = 5,
    TcpFlags = 6,
    L4SrcPort = 7,
    Ipv4SrcAddr = 8,
    SrcMask = 9,
    InputSnmp = 10,
    L4DstPort = 11,
    Ipv4DstAddr = 12,
    DstMask = 13,
    OutputSnmp = 14,
    Ipv4NextHop = 15,
    SrcAs = 16,
    DstAs = 17,
    BgpIpv4NextHop = 18,
    MulDstPkts = 19,
    MulDstBytes = 20,
    LastSwitched = 21,
    FirstSwitched = 22,
    OutBytes = 23,
    OutPkts = 24,
    Ipv6SrcAddr = 27,
    Ipv6DstAddr = 28,
    Ipv6SrcMask = 29,
    Ipv6DstMask = 30,
    Ipv6FlowLabel = 31,
    IcmpType = 32,
    MulIgmpType = 33,
    SamplingInterval = 34,
    SamplingAlgorithm = 35,
    FlowActiveTimeout = 36,
    FlowInactiveTimeout = 37,
    EngineType = 38,
    EngineId = 39,
    TotalBytesExp = 40,
    TotalPktsExp = 41,
    TotalFlowsExp = 42,
    MplsTopLabelType = 46,
    MplsTopLabelIpAddr = 47,
    FlowSamplerId = 48,
    FlowSamplerMode = 49,
    FlowSamplerRandomInterval = 50,
    DstTos = 55,
    SrcMac = 56,
    DstMac = 57,
    SrcVlan = 58,
    DstVlan = 59,
    IpProtocolVersion = 60,
    Direction = 61,
    Ipv6NextHop = 62,
    BgpIpv6NextHop = 63,
    Ipv6OptionHeaders = 64,
    MplsLabel1 = 70,
    MplsLabel2 = 71,
    MplsLabel3 = 72,
    MplsLabel4 = 73,
    MplsLabel5 = 74,
    MplsLabel6 = 75,
    MplsLabel7 = 76,
    MplsLabel8 = 77,
    MplsLabel9 = 78,
    MplsLabel10 = 79,
    Unknown(u16),
}

impl From<u16> for FieldType {
    fn from(value: u16) -> Self {
        match value {
            1 => FieldType::InBytes,
            2 => FieldType::InPkts,
            3 => FieldType::Flows,
            4 => FieldType::Protocol,
            5 => FieldType::Tos,
            6 => FieldType::TcpFlags,
            7 => FieldType::L4SrcPort,
            8 => FieldType::Ipv4SrcAddr,
            9 => FieldType::SrcMask,
            10 => FieldType::InputSnmp,
            11 => FieldType::L4DstPort,
            12 => FieldType::Ipv4DstAddr,
            13 => FieldType::DstMask,
            14 => FieldType::OutputSnmp,
            15 => FieldType::Ipv4NextHop,
            16 => FieldType::SrcAs,
            17 => FieldType::DstAs,
            18 => FieldType::BgpIpv4NextHop,
            19 => FieldType::MulDstPkts,
            20 => FieldType::MulDstBytes,
            21 => FieldType::LastSwitched,
            22 => FieldType::FirstSwitched,
            23 => FieldType::OutBytes,
            24 => FieldType::OutPkts,
            27 => FieldType::Ipv6SrcAddr,
            28 => FieldType::Ipv6DstAddr,
            29 => FieldType::Ipv6SrcMask,
            30 => FieldType::Ipv6DstMask,
            31 => FieldType::Ipv6FlowLabel,
            32 => FieldType::IcmpType,
            33 => FieldType::MulIgmpType,
            34 => FieldType::SamplingInterval,
            35 => FieldType::SamplingAlgorithm,
            36 => FieldType::FlowActiveTimeout,
            37 => FieldType::FlowInactiveTimeout,
            38 => FieldType::EngineType,
            39 => FieldType::EngineId,
            40 => FieldType::TotalBytesExp,
            41 => FieldType::TotalPktsExp,
            42 => FieldType::TotalFlowsExp,
            46 => FieldType::MplsTopLabelType,
            47 => FieldType::MplsTopLabelIpAddr,
            48 => FieldType::FlowSamplerId,
            49 => FieldType::FlowSamplerMode,
            50 => FieldType::FlowSamplerRandomInterval,
            55 => FieldType::DstTos,
            56 => FieldType::SrcMac,
            57 => FieldType::DstMac,
            58 => FieldType::SrcVlan,
            59 => FieldType::DstVlan,
            60 => FieldType::IpProtocolVersion,
            61 => FieldType::Direction,
            62 => FieldType::Ipv6NextHop,
            63 => FieldType::BgpIpv6NextHop,
            64 => FieldType::Ipv6OptionHeaders,
            70 => FieldType::MplsLabel1,
            71 => FieldType::MplsLabel2,
            72 => FieldType::MplsLabel3,
            73 => FieldType::MplsLabel4,
            74 => FieldType::MplsLabel5,
            75 => FieldType::MplsLabel6,
            76 => FieldType::MplsLabel7,
            77 => FieldType::MplsLabel8,
            78 => FieldType::MplsLabel9,
            79 => FieldType::MplsLabel10,
            _ => FieldType::Unknown(value),
        }
    }
}

impl From<FieldType> for u16 {
    fn from(field_type: FieldType) -> Self {
        match field_type {
            FieldType::InBytes => 1,
            FieldType::InPkts => 2,
            FieldType::Flows => 3,
            FieldType::Protocol => 4,
            FieldType::Tos => 5,
            FieldType::TcpFlags => 6,
            FieldType::L4SrcPort => 7,
            FieldType::Ipv4SrcAddr => 8,
            FieldType::SrcMask => 9,
            FieldType::InputSnmp => 10,
            FieldType::L4DstPort => 11,
            FieldType::Ipv4DstAddr => 12,
            FieldType::DstMask => 13,
            FieldType::OutputSnmp => 14,
            FieldType::Ipv4NextHop => 15,
            FieldType::SrcAs => 16,
            FieldType::DstAs => 17,
            FieldType::BgpIpv4NextHop => 18,
            FieldType::MulDstPkts => 19,
            FieldType::MulDstBytes => 20,
            FieldType::LastSwitched => 21,
            FieldType::FirstSwitched => 22,
            FieldType::OutBytes => 23,
            FieldType::OutPkts => 24,
            FieldType::Ipv6SrcAddr => 27,
            FieldType::Ipv6DstAddr => 28,
            FieldType::Ipv6SrcMask => 29,
            FieldType::Ipv6DstMask => 30,
            FieldType::Ipv6FlowLabel => 31,
            FieldType::IcmpType => 32,
            FieldType::MulIgmpType => 33,
            FieldType::SamplingInterval => 34,
            FieldType::SamplingAlgorithm => 35,
            FieldType::FlowActiveTimeout => 36,
            FieldType::FlowInactiveTimeout => 37,
            FieldType::EngineType => 38,
            FieldType::EngineId => 39,
            FieldType::TotalBytesExp => 40,
            FieldType::TotalPktsExp => 41,
            FieldType::TotalFlowsExp => 42,
            FieldType::MplsTopLabelType => 46,
            FieldType::MplsTopLabelIpAddr => 47,
            FieldType::FlowSamplerId => 48,
            FieldType::FlowSamplerMode => 49,
            FieldType::FlowSamplerRandomInterval => 50,
            FieldType::DstTos => 55,
            FieldType::SrcMac => 56,
            FieldType::DstMac => 57,
            FieldType::SrcVlan => 58,
            FieldType::DstVlan => 59,
            FieldType::IpProtocolVersion => 60,
            FieldType::Direction => 61,
            FieldType::Ipv6NextHop => 62,
            FieldType::BgpIpv6NextHop => 63,
            FieldType::Ipv6OptionHeaders => 64,
            FieldType::MplsLabel1 => 70,
            FieldType::MplsLabel2 => 71,
            FieldType::MplsLabel3 => 72,
            FieldType::MplsLabel4 => 73,
            FieldType::MplsLabel5 => 74,
            FieldType::MplsLabel6 => 75,
            FieldType::MplsLabel7 => 76,
            FieldType::MplsLabel8 => 77,
            FieldType::MplsLabel9 => 78,
            FieldType::MplsLabel10 => 79,
            FieldType::Unknown(value) => value,
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, Serialize, Eq, Hash, PartialEq)]
pub enum ScopeFieldType {
    System = 1,
    Interface = 2,
    LineCard = 3,
    Cache = 4,
    Template = 5,
    Unknown(u16),
}

impl From<u16> for ScopeFieldType {
    fn from(value: u16) -> Self {
        match value {
            1 => ScopeFieldType::System,
            2 => ScopeFieldType::Interface,
            3 => ScopeFieldType::LineCard,
            4 => ScopeFieldType::Cache,
            5 => ScopeFieldType::Template,
            _ => ScopeFieldType::Unknown(value),
        }
    }
}

impl From<ScopeFieldType> for u16 {
    fn from(scope_field_type: ScopeFieldType) -> Self {
        match scope_field_type {
            ScopeFieldType::System => 1,
            ScopeFieldType::Interface => 2,
            ScopeFieldType::LineCard => 3,
            ScopeFieldType::Cache => 4,
            ScopeFieldType::Template => 5,
            ScopeFieldType::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetFlowV9Parser {
    pub templates: TemplatesMap,
    pub options: FxHashMap<DataRecordFieldType, Vec<u8>>,
}

impl Default for NetFlowV9Parser {
    fn default() -> Self {
        let templates = FxHashMap::default();
        let options = FxHashMap::default();

        NetFlowV9Parser { templates, options }
    }
}

impl NetFlowV9Parser {
    pub fn parse<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Result<NetFlowV9, nom::Err<Error<&'a [u8]>, Error<&'a [u8]>>> {
        parse_netflow_v9(&self.templates)(input).map(|(_, packet)| packet)
    }

    pub fn parse_data_records<'a>(
        &'a mut self,
        input: &'a [u8],
    ) -> Result<
        Vec<FxHashMap<DataRecordFieldType, Vec<u8>>>,
        nom::Err<Error<&'a [u8]>, Error<&'a [u8]>>,
    > {
        let packet = parse_netflow_v9(&self.templates)(input).map(|(_, packet)| packet)?;

        let mut records = Vec::with_capacity(16);

        packet.flow_sets.iter().for_each(|set| {
            let is_data_options = self
                .templates
                .get(&(packet.source_id, set.flow_set_id))
                .map_or(false, |template| {
                    matches!(template, TemplateValue::OptionsTemplate(_))
                });

            set.records.iter().for_each(|record| match record {
                FlowSetRecord::Data(record) => {
                    if is_data_options {
                        for record_field in record.clone().into_iter() {
                            self.options.insert(record_field.0, record_field.1);
                        }
                    } else {
                        records.push(FxHashMap::from_iter(record.iter().map(
                            |DataRecordField(field_type, value)| {
                                (field_type.clone(), value.clone())
                            },
                        )));
                    }
                }
                FlowSetRecord::Template(template_record) => {
                    self.templates.insert(
                        (packet.source_id, template_record.template_id),
                        TemplateValue::Template(template_record.clone()),
                    );
                }
                FlowSetRecord::OptionsTemplate(options_template_flow_set) => {
                    self.templates.insert(
                        (packet.source_id, options_template_flow_set.template_id),
                        TemplateValue::OptionsTemplate(options_template_flow_set.clone()),
                    );
                }
            });
        });

        Ok(records)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV9 {
    /// NetFlow export format version number.
    pub version: u16,
    /// Number of flow sets exported in this packet, both template and data
    /// (1-30).
    pub count: u16,
    /// Current time in milliseconds since the export device booted.
    pub sys_uptime: u32,
    /// Current count of seconds since 0000 UTC 1970.
    pub unix_time: u32,
    /// Sequence counter of all export packets sent by the export device.
    pub sequence_number: u32,
    /// A 32-bit value that is used to guarantee uniqueness for all flows
    /// exported from a particular device.
    pub source_id: u32,
    /// A vector of flow sets. Each flow set can contain either template
    /// records, options template records, or data records.
    pub flow_sets: Vec<FlowSet>,
}

fn parse_netflow_v9<'a>(
    templates: &'a TemplatesMap,
) -> impl Fn(&[u8]) -> IResult<&[u8], NetFlowV9> + 'a {
    move |input| {
        let (input, version) = verify(be_u16, |i| *i == NETFLOW_V9_VERSION).parse(input)?;
        let (input, count) = be_u16(input)?;
        let (input, sys_uptime) = be_u32(input)?;
        let (input, unix_time) = be_u32(input)?;
        let (input, sequence_number) = be_u32(input)?;
        let (input, source_id) = be_u32(input)?;
        let (input, flow_sets) =
            many(count as usize, parse_flow_set(templates, source_id)).parse(input)?;

        Ok((
            input,
            NetFlowV9 {
                version,
                count,
                sys_uptime,
                unix_time,
                sequence_number,
                source_id,
                flow_sets,
            },
        ))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowSet {
    /// The FlowSet ID. Indicates the type of FlowSet.
    pub flow_set_id: u16,
    /// The length of this FlowSet. Length is the sum of the lengths of the
    /// FlowSet ID, Length itself, all Flow Records within this FlowSet, and the
    /// padding bytes, if any.
    pub length: u16,
    /// A vector of flow set records.
    pub records: Vec<FlowSetRecord>,
}

fn parse_flow_set(
    templates: &TemplatesMap,
    source_id: SourceId,
) -> impl Fn(&[u8]) -> IResult<&[u8], FlowSet> {
    move |input| {
        let (input, flow_set_id) = be_u16(input)?;
        let (input, length) = be_u16(input)?;

        let (input, flow_set_body) = take(length - 4)(input)?;

        let (_, records) = match flow_set_id {
            TEMPLATE_FLOW_SET_ID => many1(parse_template_record).parse(flow_set_body)?,
            OPTIONS_TEMPLATE_FLOW_SET_ID => {
                many1(parse_options_template_record).parse(flow_set_body)?
            }
            _ => {
                if let Some(template) = templates.get(&(source_id, flow_set_id)) {
                    many1(parse_data_record(&template)).parse(flow_set_body)?
                } else {
                    fail().parse(flow_set_body)?
                }
            }
        };

        Ok((
            input,
            FlowSet {
                flow_set_id,
                length,
                records,
            },
        ))
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum FlowSetRecord {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
    Data(DataRecord),
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldDefinition<T> {
    /// The type of the field.
    pub field_type: T,
    /// The length of the corresponding Field Type, in bytes.
    pub field_length: u16,
}

fn parse_field_definition<T: std::convert::From<u16>>(
    input: &[u8],
) -> IResult<&[u8], FieldDefinition<T>> {
    let (input, field_type) = be_u16(input)?;
    let (input, field_length) = be_u16(input)?;

    Ok((
        input,
        FieldDefinition {
            field_type: field_type.into(),
            field_length,
        },
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecord {
    /// Each of the newly generated Template Records is given a unique Template
    /// ID. This uniqueness is local to the Observation Domain that generated
    /// the Template ID.
    pub template_id: u16,
    /// The number of fields in this template record.
    pub field_count: u16,
    pub fields: Vec<FieldDefinition<FieldType>>,
}

fn parse_template_record(input: &[u8]) -> IResult<&[u8], FlowSetRecord> {
    let (input, template_id) = be_u16(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, fields) =
        many(field_count.to_usize(), parse_field_definition::<FieldType>).parse(input)?;

    Ok((
        input,
        FlowSetRecord::Template(TemplateRecord {
            template_id,
            field_count,
            fields,
        }),
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    /// Template ID of this Options Template.
    pub template_id: u16,
    /// The length in bytes of any Scope field definition contained in the
    /// Options Template Record.
    pub option_scope_length: u16,
    /// The length (in bytes) of any options field definitions contained in this
    /// Options Template Record.
    pub option_length: u16,
    pub scope_fields: Vec<FieldDefinition<ScopeFieldType>>,
    pub option_fields: Vec<FieldDefinition<FieldType>>,
}

fn parse_options_template_record(input: &[u8]) -> IResult<&[u8], FlowSetRecord> {
    let (input, template_id) = be_u16(input)?;
    let (input, option_scope_length) = be_u16(input)?;
    let (input, option_length) = be_u16(input)?;

    let (input, scope_fields) = take(option_scope_length)(input)?;
    let (_, scope_fields) = many0(parse_field_definition::<ScopeFieldType>).parse(scope_fields)?;

    let (input, option_fields) = take(option_length)(input)?;
    let (_, option_fields) = many0(parse_field_definition::<FieldType>).parse(option_fields)?;

    Ok((
        input,
        FlowSetRecord::OptionsTemplate(OptionsTemplateRecord {
            template_id,
            option_scope_length,
            option_length,
            scope_fields,
            option_fields,
        }),
    ))
}

fn parse_data_record(template: &TemplateValue) -> impl Fn(&[u8]) -> IResult<&[u8], FlowSetRecord> {
    move |input| match template {
        TemplateValue::Template(template_record) => {
            let (input, values) =
                parse_defined_fields(input, &template_record.fields, DataRecordFieldType::Field)?;

            Ok((input, FlowSetRecord::Data(values)))
        }
        TemplateValue::OptionsTemplate(options_template_record) => {
            let (input, scope_values) = parse_defined_fields(
                input,
                &options_template_record.scope_fields,
                DataRecordFieldType::ScopeField,
            )?;
            let (input, option_values) = parse_defined_fields(
                input,
                &options_template_record.option_fields,
                DataRecordFieldType::Field,
            )?;

            Ok((
                input,
                FlowSetRecord::Data([scope_values, option_values].concat()),
            ))
        }
    }
}

fn parse_defined_fields<'a, T, F>(
    mut input: &'a [u8],
    field_definitions: &[FieldDefinition<T>],
    make_drf_type: F,
) -> IResult<&'a [u8], Vec<DataRecordField>>
where
    T: Clone,
    F: Fn(T) -> DataRecordFieldType,
{
    let mut values = Vec::with_capacity(16);

    for field_def in field_definitions {
        let (input_, value_bytes) = take(field_def.field_length)(input)?;

        values.push(DataRecordField(
            make_drf_type(field_def.field_type.clone()),
            value_bytes.into(),
        ));

        input = input_;
    }

    Ok((input, values))
}

pub type DataRecord = Vec<DataRecordField>;

#[derive(Debug, Clone, Serialize, Eq, Hash, PartialEq)]
pub enum DataRecordFieldType {
    Field(FieldType),
    ScopeField(ScopeFieldType),
}

#[derive(Debug, Clone, Serialize)]
pub struct DataRecordField(pub DataRecordFieldType, pub Vec<u8>);
