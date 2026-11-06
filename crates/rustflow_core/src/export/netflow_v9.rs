//! Records exported as NetFlow v9 packets of one source ID.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::convert::{Record, Scope};
use crate::export::templated::Catalog;
use crate::export::{ExportError, unix_millis, unix_seconds, uptime};
use crate::protocol::DataSet;
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::netflow_v9::{
    Field, FlowSet, Header, OptionsTemplate, Packet, ScopeType, Template, VERSION,
};
use crate::protocol::value::{Value, natural_length};

/// Exports records as the NetFlow v9 packets of one source ID.
///
/// Templates are made and sent as the [IPFIX exporter](super::ipfix)
/// does, with what NetFlow v9 lacks: every field has a fixed length, a
/// string or octet array's being that of the first value seen; enterprise
/// elements and lists have no field and are errors. Absolute flow times are
/// sent as uptimes relative to when the exporter booted
/// (`flowStartSysUpTime`), and an options record's scope as the scope type
/// its element stands for (RFC 3954 section 6.1).
#[derive(Debug)]
pub struct Exporter {
    source_id: u32,
    boot_ms: u64,
    /// Packets sent so far, modulo 2^32.
    sequence_number: u32,
    templates: Catalog<Kind>,
}

#[derive(Debug)]
enum Kind {
    Data(Arc<Template>),
    Options(Arc<OptionsTemplate>),
}

impl Exporter {
    pub fn new(source_id: u32, boot: SystemTime) -> Self {
        Self {
            source_id,
            boot_ms: unix_millis(boot),
            sequence_number: 0,
            templates: Catalog::new(),
        }
    }

    /// Sends every template again in the first packet after `every` has
    /// passed since they were last sent. Without it, a template is sent
    /// once, and again only on [`resend_templates`](Self::resend_templates).
    pub fn with_template_refresh(mut self, every: Duration) -> Self {
        self.templates.refresh_every(every);
        self
    }

    /// Has the next packet carry every template.
    pub fn resend_templates(&mut self) {
        self.templates.resend();
    }

    /// Makes the template for records of `record`'s shape ahead of any such
    /// record, so that it goes out with the next templates rather than with
    /// the first record.
    pub fn declare(&mut self, record: &Record) -> Result<(), ExportError> {
        let boot_ms = self.boot_ms;
        self.templates
            .template_of(record, |template_id| {
                make_template(record, template_id, boot_ms)
            })
            .map(|_| ())
    }

    pub fn source_id(&self) -> u32 {
        self.source_id
    }

    /// A packet of `records`, exported at `now`, with the templates that
    /// are due before them. Records that follow one another in one shape
    /// share a FlowSet. A record with a scope is an options record, its
    /// scope values first.
    pub fn export(&mut self, records: &[Record], now: SystemTime) -> Result<Packet, ExportError> {
        // The header carries the export time in whole seconds, so the
        // uptime is taken at that second: a collector then recovers the
        // flow times to the millisecond.
        let export_ms = u64::from(unix_seconds(now)) * 1_000;
        let boot_ms = self.boot_ms;
        let mut data = Vec::new();
        for record in records {
            let template = self.templates.template_of(record, |template_id| {
                make_template(record, template_id, boot_ms)
            })?;
            let mut values: Vec<_> = record
                .scope
                .iter()
                .map(|(_, value)| value.clone())
                .collect();
            values.extend(
                record
                    .iter()
                    .map(|(element, value)| sent_value(element, value, boot_ms)),
            );
            push(&mut data, template, values);
        }

        let mut flow_sets = Vec::new();
        if self.templates.take_due(now) {
            flow_sets.extend(self.template_sets());
        }
        flow_sets.append(&mut data);

        let header = Header {
            version: VERSION,
            count: 0,
            sys_uptime: uptime(export_ms, boot_ms),
            unix_secs: unix_seconds(now),
            sequence_number: self.sequence_number,
            source_id: self.source_id,
        };
        self.sequence_number = self.sequence_number.wrapping_add(1);
        Ok(Packet { header, flow_sets })
    }

    fn template_sets(&self) -> impl Iterator<Item = FlowSet> {
        let mut data = Vec::new();
        let mut options = Vec::new();
        for template in self.templates.iter() {
            match template {
                Kind::Data(template) => data.push(Arc::clone(template)),
                Kind::Options(template) => options.push(Arc::clone(template)),
            }
        }
        let data = (!data.is_empty()).then_some(FlowSet::Templates(data));
        let options = (!options.is_empty()).then_some(FlowSet::OptionsTemplates(options));
        data.into_iter().chain(options)
    }
}

fn make_template(record: &Record, template_id: u16, boot_ms: u64) -> Result<Kind, ExportError> {
    let scope_fields = record
        .scope
        .iter()
        .map(|(scope, value)| scope_field(*scope, value))
        .collect::<Result<Vec<_>, _>>()?;
    let fields = record
        .iter()
        .map(|(element, value)| field(element, value, boot_ms))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(if scope_fields.is_empty() {
        Kind::Data(Arc::new(Template {
            template_id,
            fields,
        }))
    } else {
        Kind::Options(Arc::new(OptionsTemplate {
            template_id,
            scope_fields,
            option_fields: fields,
        }))
    })
}

/// Adds a record to the last FlowSet if it is of its template, or in a new
/// one.
fn push(sets: &mut Vec<FlowSet>, template: &Kind, values: Vec<Value>) {
    match (sets.last_mut(), template) {
        (Some(FlowSet::Data(set)), Kind::Data(template))
            if Arc::ptr_eq(&set.template, template) =>
        {
            set.records.push(values);
        }
        (Some(FlowSet::OptionsData(set)), Kind::Options(template))
            if Arc::ptr_eq(&set.template, template) =>
        {
            set.records.push(values);
        }
        (_, Kind::Data(template)) => sets.push(FlowSet::Data(DataSet {
            template: Arc::clone(template),
            records: vec![values],
        })),
        (_, Kind::Options(template)) => sets.push(FlowSet::OptionsData(DataSet {
            template: Arc::clone(template),
            records: vec![values],
        })),
    }
}

/// The field a value is sent in: an absolute flow time's as an uptime, the
/// rest as the element's.
fn field(element: ElementId, value: &Value, boot_ms: u64) -> Result<Field, ExportError> {
    if element.enterprise_number.is_some() {
        return Err(ExportError::NoField(element));
    }
    let field_type = match element {
        iana::FLOW_START_MILLISECONDS => iana::FLOW_START_SYS_UP_TIME.id,
        iana::FLOW_END_MILLISECONDS => iana::FLOW_END_SYS_UP_TIME.id,
        _ => element.id,
    };
    let length =
        fixed_length(&sent_value(element, value, boot_ms)).ok_or(ExportError::NoField(element))?;
    Ok(Field { field_type, length })
}

/// A value as sent: an absolute flow time as an uptime, the rest as it is.
fn sent_value(element: ElementId, value: &Value, boot_ms: u64) -> Value {
    match (element, value) {
        (
            iana::FLOW_START_MILLISECONDS | iana::FLOW_END_MILLISECONDS,
            Value::DateTimeMilliseconds(ms),
        ) => Value::Unsigned32(uptime(*ms, boot_ms)),
        _ => value.clone(),
    }
}

/// The scope field of an options record's scope: the scope type the
/// element stands for, the reverse of what conversion reads one as, with
/// `observationDomainId` as the System too.
fn scope_field(scope: Scope, value: &Value) -> Result<Field, ExportError> {
    let scope_type = match scope {
        Scope::Type(scope_type) => scope_type,
        Scope::Element(element) => match element {
            iana::EXPORTING_PROCESS_ID | iana::OBSERVATION_DOMAIN_ID => ScopeType::System,
            iana::INGRESS_INTERFACE => ScopeType::Interface,
            iana::LINE_CARD_ID => ScopeType::LineCard,
            iana::METERING_PROCESS_ID => ScopeType::Cache,
            iana::TEMPLATE_ID => ScopeType::Template,
            _ => return Err(ExportError::ScopeElement(element)),
        },
    };
    let length = fixed_length(value).ok_or(match scope {
        Scope::Element(element) => ExportError::ScopeElement(element),
        Scope::Type(scope_type) => ExportError::Scope(scope_type),
    })?;
    Ok(Field {
        field_type: scope_type.into(),
        length,
    })
}

/// A value's length in a field that has one: its type's, or its own for a
/// string or an octet array, with a null taking one zero byte as no field
/// is empty. A list has none.
fn fixed_length(value: &Value) -> Option<u16> {
    u16::try_from(natural_length(value)?.max(1)).ok()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::convert::{self, Elements, Protocol, Received};
    use crate::protocol::information_element::Registry;
    use crate::protocol::netflow_v9;

    const SOURCE_ID: u32 = 3;
    const BOOT_MS: u64 = 1_700_000_000_000;
    const START_MS: u64 = BOOT_MS + 90_000;
    const END_MS: u64 = BOOT_MS + 95_500;

    fn at_ms(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms)
    }

    fn record(scope: Vec<(Scope, Value)>, fields: &[(ElementId, Value)]) -> Record {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Record {
            protocol: Protocol::NetflowV9,
            sequence_number: 0,
            scope,
            elements: Arc::new(Elements::from(elements)),
            values,
        }
    }

    fn flow(octets: u64) -> Record {
        record(
            Vec::new(),
            &[
                (
                    iana::SOURCE_IPV4_ADDRESS,
                    Value::Ipv4Address([10, 0, 0, 1].into()),
                ),
                (iana::OCTET_DELTA_COUNT, Value::Unsigned64(octets)),
                (iana::INTERFACE_NAME, Value::String("eth0".into())),
                (
                    iana::FLOW_START_MILLISECONDS,
                    Value::DateTimeMilliseconds(START_MS),
                ),
                (
                    iana::FLOW_END_MILLISECONDS,
                    Value::DateTimeMilliseconds(END_MS),
                ),
            ],
        )
    }

    fn sampling_options(interval: u32) -> Record {
        record(
            vec![(
                Scope::Element(iana::OBSERVATION_DOMAIN_ID),
                Value::Unsigned32(SOURCE_ID),
            )],
            &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(interval))],
        )
    }

    fn set_ids(packet: &Packet) -> Vec<&'static str> {
        packet
            .flow_sets
            .iter()
            .map(|set| match set {
                FlowSet::Templates(_) => "templates",
                FlowSet::OptionsTemplates(_) => "options templates",
                FlowSet::Data(_) => "data",
                FlowSet::OptionsData(_) => "options data",
                FlowSet::Undecoded { .. } => "undecoded",
                FlowSet::Unknown(_) => "unknown",
            })
            .collect()
    }

    /// `packet` as a collector reads it: written, parsed and converted.
    fn collected(parser: &mut netflow_v9::Parser, packet: &Packet) -> Vec<Record> {
        let mut buf = Vec::new();
        netflow_v9::write(packet, &mut buf).unwrap();
        let parsed = parser.parse(&buf).unwrap();
        let received = Received {
            exporter: SocketAddr::from(([192, 0, 2, 1], 2055)),
            time: None,
        };
        let mut records = Vec::new();
        convert::netflow_v9::Converter::default().convert(parsed, &received, &mut records);
        records
    }

    #[test]
    fn records_come_back_through_a_collector_as_they_went() {
        let mut exporter = Exporter::new(SOURCE_ID, at_ms(BOOT_MS));
        let sent = [sampling_options(64), flow(100), flow(200)];
        let now = at_ms(BOOT_MS + 100_000 + 250);
        let packet = exporter.export(&sent, now).unwrap();
        assert_eq!(
            set_ids(&packet),
            ["templates", "options templates", "options data", "data"]
        );
        assert_eq!(packet.header.sys_uptime, 100_000, "at the whole second");
        assert_eq!(packet.header.unix_secs, 1_700_000_100);
        assert_eq!(packet.header.source_id, SOURCE_ID);

        let mut parser = netflow_v9::Parser::new(Registry::iana(), Duration::from_secs(60));
        let records = collected(&mut parser, &packet);
        assert_eq!(records.len(), sent.len());
        for (sent, received) in sent.iter().zip(&records) {
            for (element, value) in sent.iter() {
                assert_eq!(received.first(element), Some(value), "{element}");
            }
        }
        assert_eq!(
            records[0].scope,
            vec![(
                Scope::Element(iana::EXPORTING_PROCESS_ID),
                Value::Unsigned32(SOURCE_ID)
            )],
            "the System scope"
        );
        assert_eq!(
            records[1].first(iana::SAMPLING_PACKET_SPACE),
            Some(&Value::Unsigned32(63)),
            "the options applied to the flows after them"
        );

        let later = exporter
            .export(&[flow(300)], at_ms(BOOT_MS + 101_000))
            .unwrap();
        assert_eq!(set_ids(&later), ["data"]);
        assert_eq!(later.header.sequence_number, 1, "packets are counted");
        assert_eq!(collected(&mut parser, &later).len(), 1);
    }

    #[test]
    fn times_go_as_uptimes_and_strings_at_their_length() {
        let mut exporter = Exporter::new(SOURCE_ID, at_ms(BOOT_MS));
        let packet = exporter
            .export(&[flow(1)], at_ms(BOOT_MS + 100_000))
            .unwrap();
        let FlowSet::Templates(templates) = &packet.flow_sets[0] else {
            unreachable!()
        };
        let fields: Vec<_> = templates[0]
            .fields
            .iter()
            .map(|field| (field.field_type, field.length))
            .collect();
        assert_eq!(fields, [(8, 4), (1, 8), (82, 4), (22, 4), (21, 4)]);
        let FlowSet::Data(data) = &packet.flow_sets[1] else {
            unreachable!()
        };
        assert_eq!(data.records[0][3], Value::Unsigned32(90_000));
        assert_eq!(data.records[0][4], Value::Unsigned32(95_500));
    }

    #[test]
    fn what_netflow_v9_cannot_carry_is_an_error() {
        let mut exporter = Exporter::new(SOURCE_ID, at_ms(BOOT_MS));
        let enterprise = ElementId::from((9, 1));
        let foreign = record(Vec::new(), &[(enterprise, Value::Unsigned32(1))]);
        assert_eq!(
            exporter.export(&[foreign], at_ms(BOOT_MS)),
            Err(ExportError::NoField(enterprise))
        );
        let scoped = record(
            vec![(
                Scope::Element(iana::OCTET_DELTA_COUNT),
                Value::Unsigned64(1),
            )],
            &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(1))],
        );
        assert_eq!(
            exporter.export(&[scoped], at_ms(BOOT_MS)),
            Err(ExportError::ScopeElement(iana::OCTET_DELTA_COUNT))
        );
    }

    #[test]
    fn a_scope_type_without_an_element_is_sent_as_it_is() {
        let mut exporter = Exporter::new(SOURCE_ID, at_ms(BOOT_MS));
        let record = record(
            vec![(Scope::Type(ScopeType::Unassigned(7)), Value::Unsigned32(1))],
            &[(iana::SAMPLING_INTERVAL, Value::Unsigned32(1))],
        );
        let packet = exporter.export(&[record], at_ms(BOOT_MS)).unwrap();
        let FlowSet::OptionsTemplates(templates) = &packet.flow_sets[0] else {
            unreachable!()
        };
        assert_eq!(templates[0].scope_fields[0].field_type, 7);
    }
}
