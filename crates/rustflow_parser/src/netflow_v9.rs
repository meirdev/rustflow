use nom::Parser;
use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::{all_consuming, peek, verify};
use nom::multi::{length_data, many, many1};
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::preceded;
use nom::{IResult, ToUsize};
use std::collections::HashMap;

// Netflow V9
// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html

pub enum FieldType {
    /// Incoming counter with length N x 8 bits for number of bytes associated with an IP Flow.
    InBytes = 1,
    /// Incoming counter with length N x 8 bits for the number of packets associated with an IP Flow.
    InPkts = 2,
    /// Number of flows that were aggregated. default for N is 4.
    Flows = 3,
    /// IP protocol byte
    Protocol = 4,
    /// Type of Service byte setting when entering incoming interface.
    SrcTos = 5,
    /// Cumulative of all the TCP flags seen for this flow.
    TcpFlags = 6,
    /// TCP/UDP source port number i.e.: FTP, Telnet, or equivalent.
    L4SrcPort = 7,
    /// IPv4 source address.
    IPv4SrcAddr = 8,
    /// The number of contiguous bits in the source address subnet mask i.e.: the submask in slash notation.
    SrcMask = 9,
    /// Input interface index; default for N is 2 but higher values could be used.
    InputSnmp = 10,
    /// TCP/UDP destination port number i.e.: FTP, Telnet, or equivalent.
    L4DstPort = 11,
    /// IPv4 destination address.
    Ipv4DstAddr = 12,
    /// The number of contiguous bits in the destination address subnet mask i.e.: the submask in slash notation.
    DstMask = 13,
    /// Output interface index; default for N is 2 but higher values could be used.
    OutputSnmp = 14,
    /// IPv4 address of next-hop router.
    Ipv4NextHop = 15,
    /// Source BGP autonomous system number where N could be 2 or 4.
    SrcAs = 16,
    /// Destination BGP autonomous system number where N could be 2 or 4.
    DstAs = 17,
    /// Next-hop router's IP in the BGP domain.
    BgpNextHop = 18,
    /// IP multicast outgoing packet counter with length N x 8 bits for packets associated with the IP Flow.
    MulDstPkts = 19,
    /// IP multicast outgoing byte counter with length N x 8 bits for bytes associated with the IP Flow.
    MulDstBytes = 20,
    /// System uptime at which the last packet of this flow was switched.
    LastSwitched = 21,
    /// System uptime at which the first packet of this flow was switched.
    FirstSwitched = 22,
    /// Outgoing counter with length N x 8 bits for the number of bytes associated with an IP Flow.
    OutBytes = 23,
    /// Outgoing counter with length N x 8 bits for the number of packets associated with an IP Flow.
    OutPkts = 24,
    /// Minimum IP packet length on incoming packets of the flow.
    MinPktLnght = 25,
    /// Maximum IP packet length on incoming packets of the flow.
    MaxPktLnght = 26,
    /// IPv6 Source Address.
    Ipv6SrcAddr = 27,
    /// IPv6 Destination Address.
    Ipv6DstAddr = 28,
    /// Length of the IPv6 source mask in contiguous bits.
    Ipv6SrcMask = 29,
    /// Length of the IPv6 destination mask in contiguous bits.
    Ipv6DstMask = 30,
    /// IPv6 flow label as per RFC 2460 definition.
    Ipv6FlowLabel = 31,
    /// Internet Control Message Protocol (ICMP) packet type; reported as ((ICMP Type*256) + ICMP code).
    IcmpType = 32,
    /// Internet Group Management Protocol (IGMP) packet type.
    MulIgmpType = 33,
    /// When using sampled NetFlow, the rate at which packets are sampled i.e.: a value of 100 indicates that one of every 100 packets is sampled.
    SamplingInterval = 34,
    /// The type of algorithm used for sampled NetFlow: 0x01 Deterministic Sampling, 0x02 Random Sampling.
    SamplingAlgorithm = 35,
    /// Timeout value (in seconds) for active flow entries in the NetFlow cache.
    FlowActiveTimeout = 36,
    /// Timeout value (in seconds) for inactive flow entries in the NetFlow cache.
    FlowInactiveTimeout = 37,
    /// Type of flow switching engine: RP = 0, VIP/Linecard = 1.
    EngineType = 38,
    /// ID number of the flow switching engine.
    EngineId = 39,
    /// Counter with length N x 8 bits for bytes for the number of bytes exported by the Observation Domain.
    TotalBytesExp = 40,
    /// Counter with length N x 8 bits for bytes for the number of packets exported by the Observation Domain.
    TotalPktsExp = 41,
    /// Counter with length N x 8 bits for bytes for the number of flows exported by the Observation Domain.
    TotalFlowsExp = 42,
    VendorProprietary1 = 43,
    /// IPv4 source address prefix (specific for Catalyst architecture).
    Ipv4SrcPrefix = 44,
    /// IPv4 destination address prefix (specific for Catalyst architecture).
    Ipv4DstPrefix = 45,
    /// MPLS Top Label Type: 0x00 UNKNOWN 0x01 TE-MIDPT 0x02 ATOM 0x03 VPN 0x04 BGP 0x05 LDP.
    MplsTopLabelType = 46,
    /// Forwarding Equivalent Class corresponding to the MPLS Top Label.
    MplsTopLabelIpAddr = 47,
    /// Identifier shown in "show flow-sampler".
    FlowSamplerId = 48,
    /// The type of algorithm used for sampling data: 0x02 random sampling. Use in connection with FLOW_SAMPLER_MODE.
    FlowSamplerMode = 49,
    /// Packet interval at which to sample. Use in connection with FLOW_SAMPLER_MODE.
    FlowSamplerRandomInterval = 50,
    VendorProprietary2 = 51,
    /// Minimum TTL on incoming packets of the flow.
    MinTtl = 52,
    /// Maximum TTL on incoming packets of the flow.
    MaxTtl = 53,
    /// The IP v4 identification field.
    Ipv4Ident = 54,
    /// Type of Service byte setting when exiting outgoing interface.
    DstTos = 55,
    /// Incoming source MAC address.
    InSrcMac = 56,
    /// Outgoing destination MAC address.
    OutDstMac = 57,
    /// Virtual LAN identifier associated with ingress interface.
    SrcVlan = 58,
    /// Virtual LAN identifier associated with egress interface.
    DstVlan = 59,
    /// Internet Protocol Version Set to 4 for IPv4, set to 6 for IPv6. If not present in the template, then version 4 is assumed.
    IpProtocolVersion = 60,
    /// Flow direction: 0 - ingress flow, 1 - egress flow.
    Direction = 61,
    /// IPv6 address of the next-hop router.
    Ipv6NextHop = 62,
    /// Next-hop router in the BGP domain.
    BgpIpv6NextHop = 63,
    /// Bit-encoded field identifying IPv6 option headers found in the flow.
    Ipv6OptionHeaders = 64,
    VendorProprietary3 = 65,
    VendorProprietary4 = 66,
    VendorProprietary5 = 67,
    VendorProprietary6 = 68,
    VendorProprietary7 = 69,
    /// MPLS label at position 1 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel1 = 70,
    /// MPLS label at position 2 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel2 = 71,
    /// MPLS label at position 3 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel3 = 72,
    /// MPLS label at position 4 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel4 = 73,
    /// MPLS label at position 5 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel5 = 74,
    /// MPLS label at position 6 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel6 = 75,
    /// MPLS label at position 7 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel7 = 76,
    /// MPLS label at position 8 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel8 = 77,
    /// MPLS label at position 9 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel9 = 78,
    /// MPLS label at position 10 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    MplsLabel10 = 79,
    /// Incoming source MAC address.
    InDstMac = 80,
    /// Outgoing destination MAC address.
    OutSrcMac = 81,
    /// Shortened interface name i.e.: "FE1/0".
    IfName = 82,
    /// Full interface name i.e.: "FastEthernet 1/0".
    IfDesc = 83,
    /// Name of the flow sampler.
    SamplerName = 84,
    /// Running byte counter for a permanent flow.
    InPermanentBytes = 85,
    /// Running packet counter for a permanent flow.
    InPermanentPkts = 86,
    VendorProprietary8 = 87,
    /// The fragment-offset value from fragmented IP packets.
    FragmentOffset = 88,
    /// Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code.
    /// Status is either unknown (00), Forwarded (10), Dropped (10) or Consumed (11).
    /// Below is the list of forwarding status values with their means:
    /// Unknown
    /// * 0
    /// Forwarded
    /// * Unknown 64
    /// * Forwarded Fragmented 65
    /// * Forwarded not Fragmented 66
    /// Dropped
    /// * Unknown 128
    /// * Drop ACL Deny 129
    /// * Drop ACL drop 130
    /// * Drop Unroutable 131
    /// * Drop Adjacency 132
    /// * Drop Fragmentation & DF set 133
    /// * Drop Bad header checksum 134
    /// * Drop Bad total Length 135
    /// * Drop Bad Header Length 136
    /// * Drop bad TTL 137
    /// * Drop Policer 138
    /// * Drop WRED 139
    /// * Drop RPF 140
    /// * Drop For us 141
    /// * Drop Bad output interface 142
    /// * Drop Hardware 143
    /// Consumed
    /// * Unknown 192
    /// * Terminate Punt Adjacency 193
    /// * Terminate Incomplete Adjacency 194
    /// * Terminate For us 195
    ForwardingStatus = 89,
    /// MPLS PAL Route Distinguisher.
    MplsPalRd = 90,
    /// Number of consecutive bits in the MPLS prefix length.
    MplsPrefixLen = 91,
    /// BGP Policy Accounting Source Traffic Index.
    SrcTrafficIndex = 92,
    /// BGP Policy Accounting Destination Traffic Index.
    DstTrafficIndex = 93,
    /// Application description.
    ApplicationDescription = 94,
    /// 8 bits of engine ID, followed by n bits of classification.
    ApplicationTag = 95,
    /// Name associated with a classification.
    ApplicationName = 96,
    /// The value of a Differentiated Services Code Point (DSCP) encoded in the Differentiated Services Field, after modification.
    PostIpDiffServCodePoint = 98,
    /// Multicast replication factor.
    ReplicationFactor = 99,
    /// DEPRECATED
    Deprecated = 100,
    /// Layer 2 packet section offset. Potentially a generic offset.
    Layer2PacketSectionOffset = 102,
    /// Layer 2 packet section size. Potentially a generic size.
    Layer2PacketSectionSize = 103,
    /// Layer 2 packet section data.
    Layer2PacketSectionData = 104,
    // 105 to 127. **Reserved for future use by cisco**
}

#[derive(Debug)]
pub struct NetFlowV9<'a> {
    header: Header,
    flow_set: Vec<FlowSet<'a>>,
}

#[derive(Debug, Clone)]
pub struct Header {
    /// The version of NetFlow records exported in this packet.
    version: u16,
    /// Number of FlowSet records (both template and data) contained within this packet.
    count: u16,
    /// Time in milliseconds since this device was first booted.
    system_uptime: u32,
    /// Seconds since 0000 Coordinated Universal Time (UTC) 1970.
    unix_seconds: u32,
    /// Incremental sequence counter of all export packets sent by this export device; this value is cumulative, and it can be used to identify whether any export packets have been missed.
    package_sequence: u32,
    /// The Source ID field is a 32-bit value that is used to guarantee uniqueness for all flows exported from a particular device.
    source_id: u32,
}

#[derive(Debug, Clone)]
pub struct TemplateRecordField {
    /// This numeric value represents the type of the field. The possible values of the field type are vendor specific.
    field_type: u16,
    /// This number gives the length of the above-defined field, in bytes.
    length: u16,
}

#[derive(Debug, Clone)]
pub struct TemplateRecord {
    /// As a router generates different template FlowSets to match the type of NetFlow data it will be exporting, each template is given a unique ID. This uniqueness is local to the router that generated the template ID.
    /// Templates that define data record formats begin numbering at 256 since 0-255 are reserved for FlowSet IDs.
    template_id: u16,
    /// This field gives the number of fields in this template record. Because a template FlowSet may contain multiple template records, this field allows the parser to determine the end of the current template record and the start of the next.
    field_count: u16,
    /// This field is a list of fields that are exported in the data records that follow this template record. The fields are described by the type and length of each field.
    fields: Vec<TemplateRecordField>,
}

#[derive(Debug, Clone)]
pub struct TemplateFlowSet {
    /// The FlowSet ID is used to distinguish template records from data records. A template record always has a FlowSet ID in the range of 0-255. Currently, the template record that describes flow fields has a FlowSet ID of zero and the template record that describes option fields (described below) has a FlowSet ID of 1. A data record always has a nonzero FlowSet ID greater than 255.
    flow_set_id: u16,
    /// Length refers to the total length of this FlowSet. Because an individual template FlowSet may contain multiple template IDs (as illustrated above), the length value should be used to determine the position of the next FlowSet record, which could be either a template or a data FlowSet.
    /// Length is expressed in Type/Length/Value (TLV) format, meaning that the value includes the bytes used for the FlowSet ID and the length bytes themselves, as well as the combined lengths of all template records included in this FlowSet.
    length: u16,
    /// Template records.
    template_records: Vec<TemplateRecord>,
}

#[derive(Debug, Clone)]
pub struct OptionsTemplateScopeField {
    /// This field gives the relevant portion of the NetFlow process to which the options record refers.
    /// Currently, defined values follow:
    /// * 0x0001 System
    /// * 0x0002 Interface
    /// * 0x0003 Line Card
    /// * 0x0004 NetFlow Cache
    /// * 0x0005 Template
    field_type: u16,
    /// This field gives the length (in bytes) of the Scope field, as it would appear in an options record.
    length: u16,
}

#[derive(Debug, Clone)]
pub struct OptionsTemplateOptionField {
    /// This numeric value represents the type of the field that appears in the options record.
    field_type: u16,
    /// This number is the length (in bytes) of the field, as it would appear in an options record.
    length: u16,
}

#[derive(Debug, Clone)]
pub struct OptionsTemplate {
    /// The FlowSet ID is used to distinguish template records from data records. A template record always has a FlowSet ID of 1.
    flow_set_id: u16,
    /// This field gives the total length of this FlowSet. Because an individual template FlowSet may contain multiple template IDs, the length value should be used to determine the position of the next FlowSet record, which could be either a template or a data FlowSet.
    /// Length is expressed in TLV format, meaning that the value includes the bytes used for the FlowSet ID and the length bytes themselves, as well as the combined lengths of all template records included in this FlowSet.
    length: u16,
    /// As a router generates different template FlowSets to match the type of NetFlow data it will be exporting, each template is given a unique ID.
    /// This uniqueness is local to the router that generated the template ID.
    /// The Template ID is greater than 255. Template IDs inferior to 255 are reserved.
    template_id: u16,
    /// This field gives the length in bytes of any scope fields contained in this options template.
    option_scope_length: u16,
    /// This field gives the length (in bytes) of any Options field definitions contained in this options template.
    option_length: u16,
    /// List of scope fields.
    scope_fields: Vec<OptionsTemplateScopeField>,
    /// List of option fields.
    option_fields: Vec<OptionsTemplateOptionField>,
}

#[derive(Debug, Clone)]
pub struct DataFlowSet<'a> {
    /// A FlowSet ID precedes each group of records within a NetFlow Version 9 data FlowSet. The FlowSet ID maps to a (previously received) template ID. The collector and display applications should use the FlowSet ID to map the appropriate type and length to any field values that follow.
    flow_set_id: u16,
    /// This field gives the length of the data FlowSet.
    /// Length is expressed in TLV format, meaning that the value includes the bytes used for the FlowSet ID and the length bytes themselves, as well as the combined lengths of any included data records.
    length: u16,
    /// The remainder of the Version 9 data FlowSet is a collection of field values. The type and length of the fields have been previously defined in the template record referenced by the FlowSet ID/template ID.
    data_records: Vec<Vec<&'a [u8]>>,
    // Padding should be inserted to align the end of the FlowSet on a 32 bit boundary. Pay attention that the Length field will include those padding bits.
    // padding: u16,
}

#[derive(Debug, Clone)]
pub enum FlowSet<'a> {
    Template(TemplateFlowSet),
    Data(DataFlowSet<'a>),
    OptionsTemplate(OptionsTemplate),
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, version) = verify(be_u16, |i| *i == 9).parse(input)?;
    let (input, count) = be_u16(input)?;
    let (input, system_uptime) = be_u32(input)?;
    let (input, unix_seconds) = be_u32(input)?;
    let (input, package_sequence) = be_u32(input)?;
    let (input, source_id) = be_u32(input)?;

    Ok((
        input,
        Header {
            version,
            count,
            system_uptime,
            unix_seconds,
            package_sequence,
            source_id,
        },
    ))
}

fn parse_template_record_field(input: &[u8]) -> IResult<&[u8], TemplateRecordField> {
    let (input, field_type) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, TemplateRecordField { field_type, length }))
}

fn parse_template_record(input: &[u8]) -> IResult<&[u8], TemplateRecord> {
    let (input, template_id) = verify(be_u16, |i| *i > 255).parse(input)?;
    let (input, field_count) = be_u16(input)?;
    let (input, fields) =
        many(0..=field_count.to_usize(), parse_template_record_field).parse(input)?;

    Ok((
        input,
        TemplateRecord {
            template_id,
            field_count,
            fields,
        },
    ))
}

fn parse_template_flow_set(input: &[u8]) -> IResult<&[u8], FlowSet> {
    let (rest, input) = length_data(peek(preceded(be_u16, be_u16))).parse(input)?;

    let (input, flow_set_id) = verify(be_u16, |i| (0..=255).contains(i)).parse(input)?;
    let (input, length) = be_u16(input)?;

    let (_, template_records) = all_consuming(many1(parse_template_record)).parse(input)?;

    Ok((
        rest,
        FlowSet::Template(TemplateFlowSet {
            flow_set_id,
            length,
            template_records,
        }),
    ))
}

fn parse_data_record(template: &TemplateRecord) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    move |input| {
        let mut input = input;
        let mut values = Vec::new();

        for field in template.fields.iter() {
            let (input_, value) = take(field.length)(input)?;

            values.push(value);

            input = input_;
        }

        Ok((input, values))
    }
}

fn parse_data_flow_set(
    templates: &HashMap<u16, TemplateRecord>,
) -> impl Fn(&[u8]) -> IResult<&[u8], FlowSet> {
    move |input| {
        let (input, flow_set_id) = verify(be_u16, |i| templates.contains_key(i)).parse(input)?;
        let (input, length) = be_u16(input)?;

        let template_record = templates.get(&flow_set_id).unwrap();

        let (input, data_records) = many(0.., parse_data_record(template_record)).parse(input)?;
        // let (input, padding) = be_u16(input)?;

        Ok((
            input,
            FlowSet::Data(DataFlowSet {
                flow_set_id,
                length,
                data_records,
                // padding,
            }),
        ))
    }
}

fn parse_options_template_scope_field(input: &[u8]) -> IResult<&[u8], OptionsTemplateScopeField> {
    let (input, field_type) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, OptionsTemplateScopeField { field_type, length }))
}

fn parse_options_template_option_field(input: &[u8]) -> IResult<&[u8], OptionsTemplateOptionField> {
    let (input, field_type) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, OptionsTemplateOptionField { field_type, length }))
}

fn parse_options_template(input: &[u8]) -> IResult<&[u8], FlowSet> {
    let (input, flow_set_id) = verify(be_u16, |i| *i == 1).parse(input)?;
    let (input, length) = be_u16(input)?;
    let (input, template_id) = be_u16(input)?;
    let (input, option_scope_length) = be_u16(input)?;
    let (input, option_length) = be_u16(input)?;

    let (input, scope_fields) = take(option_scope_length)(input)?;
    let (_, scope_fields) = many1(parse_options_template_scope_field).parse(scope_fields)?;

    let (input, option_fields) = take(option_length)(input)?;
    let (_, option_fields) = many1(parse_options_template_option_field).parse(option_fields)?;

    Ok((
        input,
        FlowSet::OptionsTemplate(OptionsTemplate {
            flow_set_id,
            length,
            template_id,
            option_scope_length,
            option_length,
            scope_fields,
            option_fields,
        }),
    ))
}

pub fn parse(
    templates: &mut HashMap<u16, TemplateRecord>,
) -> impl FnMut(&[u8]) -> IResult<&[u8], (Header, Vec<FlowSet>)> {
    move |input| {
        let (input, header) = parse_header(input)?;
        let (input, flow_set) = many1(alt((
            parse_template_flow_set,
            parse_options_template,
            parse_data_flow_set(templates),
        )))
        .parse(input)?;

        for flow_set in flow_set.iter() {
            match flow_set {
                FlowSet::Template(template_flow_set) => {
                    for template in template_flow_set.template_records.iter() {
                        templates.insert(template.template_id, template.clone());
                    }
                }
                _ => {}
            }
        }

        Ok((input, (header, flow_set)))
    }
}
