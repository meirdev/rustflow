use serde::Serialize;

pub const NETFLOW_V9_VERSION: u16 = 9;

pub const TEMPLATE_FLOW_SET_ID: u16 = 0;

pub const OPTIONS_TEMPLATE_FLOW_SET_ID: u16 = 1;

#[repr(u16)]
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct NetFlowV9 {
    pub header: Header,
    pub flow_sets: Vec<FlowSet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub version: u16,
    pub count: u16,
    pub sys_up_time: u32,
    pub unix_secs: u32,
    pub sequence_number: u32,
    pub source_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub enum FlowSet {
    Template(TemplateFlowSet),
    Data(DataFlowSet),
    OptionsTemplate(OptionsTemplateFlowSet),
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldDefinition<T> {
    pub field_type: T,
    pub field_length: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRecord {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: Vec<FieldDefinition<FieldType>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateFlowSet {
    pub flow_set_id: u16,
    pub length: u16,
    pub records: Vec<TemplateRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateRecord {
    pub template_id: u16,
    pub option_scope_length: u16,
    pub option_length: u16,
    pub scope_fields: Vec<FieldDefinition<ScopeFieldType>>,
    pub option_fields: Vec<FieldDefinition<FieldType>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OptionsTemplateFlowSet {
    pub flow_set_id: u16,
    pub length: u16,
    pub records: Vec<OptionsTemplateRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataFlowSet {
    pub flow_set_id: u16,
    pub length: u16,
    pub records: Vec<DataRecord>,
}

pub type DataRecord = Vec<DataRecordField>;

#[derive(Debug, Clone, Serialize)]
pub enum TemplateRecordType {
    Template(TemplateRecord),
    OptionsTemplate(OptionsTemplateRecord),
}

#[derive(Debug, Clone, Serialize)]
pub enum DataRecordFieldType {
    Field(FieldType),
    ScopeField(ScopeFieldType),
}

#[derive(Debug, Clone, Serialize)]
pub struct DataRecordField(pub DataRecordFieldType, pub Vec<u8>);
