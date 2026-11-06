//! Records exported as IPFIX messages of one observation domain.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::convert::{Record, Scope};
use crate::export::templated::Catalog;
use crate::export::{ExportError, unix_seconds};
use crate::protocol::DataSet;
use crate::protocol::information_element::ElementId;
use crate::protocol::ipfix::{
    FieldSpecifier, Header, OptionsTemplate, Packet, Set, Template, TemplateRef, VARIABLE_LENGTH,
    VERSION,
};
use crate::protocol::value::{Value, natural_length};

/// Exports records as the IPFIX messages of one observation domain.
///
/// Records of one shape, the same scope and elements, share a template,
/// made from the first record of the shape: each field as wide as its
/// value's type, or variable-length for a string, an octet array or a list.
/// A message carries every template before the first data record of a new
/// shape, and again once the refresh interval has passed, as a collector
/// over UDP needs (RFC 7011 section 8.4).
#[derive(Debug)]
pub struct Exporter {
    observation_domain_id: u32,
    /// Data records sent so far, modulo 2^32.
    sequence_number: u32,
    templates: Catalog<TemplateRef>,
}

impl Exporter {
    pub fn new(observation_domain_id: u32) -> Self {
        Self {
            observation_domain_id,
            sequence_number: 0,
            templates: Catalog::new(),
        }
    }

    /// Sends every template again in the first message after `every` has
    /// passed since they were last sent. Without it, a template is sent
    /// once, and again only on [`resend_templates`](Self::resend_templates).
    pub fn with_template_refresh(mut self, every: Duration) -> Self {
        self.templates.refresh_every(every);
        self
    }

    /// Has the next message carry every template.
    pub fn resend_templates(&mut self) {
        self.templates.resend();
    }

    pub fn observation_domain_id(&self) -> u32 {
        self.observation_domain_id
    }

    /// The templates the exporter has made, in the order it made them.
    pub fn templates(&self) -> impl Iterator<Item = &TemplateRef> {
        self.templates.iter()
    }

    /// A message of `records`, exported at `now`, with the templates that
    /// are due before them. Records that follow one another in one shape
    /// share a set. A record with a scope is an options record, its scope
    /// values first.
    pub fn export(&mut self, records: &[Record], now: SystemTime) -> Result<Packet, ExportError> {
        let mut data = Vec::new();
        for record in records {
            let template = self
                .templates
                .template_of(record, |template_id| make_template(record, template_id))?;
            let values = record
                .scope
                .iter()
                .map(|(_, value)| value)
                .chain(&record.values)
                .cloned()
                .collect();
            push(&mut data, template, values);
        }

        let mut sets = Vec::new();
        if self.templates.take_due(now) {
            sets.extend(self.template_sets());
        }
        sets.append(&mut data);

        let header = Header {
            version: VERSION,
            length: 0,
            export_time: unix_seconds(now),
            sequence_number: self.sequence_number,
            observation_domain_id: self.observation_domain_id,
        };
        self.sequence_number = self
            .sequence_number
            .wrapping_add(u32::try_from(records.len()).unwrap_or(u32::MAX));
        Ok(Packet { header, sets })
    }

    fn template_sets(&self) -> impl Iterator<Item = Set> {
        let mut data = Vec::new();
        let mut options = Vec::new();
        for template in self.templates() {
            match template {
                TemplateRef::Data(template) => data.push(Arc::clone(template)),
                TemplateRef::Options(template) => options.push(Arc::clone(template)),
            }
        }
        let data = (!data.is_empty()).then_some(Set::Templates(data));
        let options = (!options.is_empty()).then_some(Set::OptionsTemplates(options));
        data.into_iter().chain(options)
    }
}

fn make_template(record: &Record, template_id: u16) -> Result<TemplateRef, ExportError> {
    let mut scope_fields = Vec::with_capacity(record.scope.len());
    for (scope, value) in &record.scope {
        match scope {
            Scope::Element(element) => scope_fields.push(field(*element, value)),
            Scope::Type(scope_type) => return Err(ExportError::Scope(*scope_type)),
        }
    }
    let fields = record
        .iter()
        .map(|(element, value)| field(element, value))
        .collect();
    Ok(if scope_fields.is_empty() {
        TemplateRef::Data(Arc::new(Template {
            template_id,
            fields,
        }))
    } else {
        TemplateRef::Options(Arc::new(OptionsTemplate {
            template_id,
            scope_fields,
            option_fields: fields,
        }))
    })
}

/// Adds a record to the last set if it is of its template, or in a new set.
fn push(sets: &mut Vec<Set>, template: &TemplateRef, values: Vec<Value>) {
    match (sets.last_mut(), template) {
        (Some(Set::Data(set)), TemplateRef::Data(template))
            if Arc::ptr_eq(&set.template, template) =>
        {
            set.records.push(values);
        }
        (Some(Set::OptionsData(set)), TemplateRef::Options(template))
            if Arc::ptr_eq(&set.template, template) =>
        {
            set.records.push(values);
        }
        (_, TemplateRef::Data(template)) => sets.push(Set::Data(DataSet {
            template: Arc::clone(template),
            records: vec![values],
        })),
        (_, TemplateRef::Options(template)) => sets.push(Set::OptionsData(DataSet {
            template: Arc::clone(template),
            records: vec![values],
        })),
    }
}

/// The field a value is sent in: as wide as its type, or variable-length
/// when its length is its own (RFC 7011 section 7).
fn field(element: ElementId, value: &Value) -> FieldSpecifier {
    let field_length = match value {
        Value::OctetArray(_) | Value::String(_) | Value::Null => VARIABLE_LENGTH,
        _ => natural_length(value).map_or(VARIABLE_LENGTH, |length| length as u16),
    };
    FieldSpecifier {
        information_element_id: element.id,
        field_length,
        enterprise_number: element.enterprise_number,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::convert::{self, Elements, Protocol, Received};
    use crate::protocol::information_element::{Registry, iana};
    use crate::protocol::ipfix;

    const DOMAIN: u32 = 7;
    const NOW: SystemTime = UNIX_EPOCH;

    fn at(seconds: u64) -> SystemTime {
        NOW + Duration::from_secs(seconds)
    }

    fn record(scope: Vec<(Scope, Value)>, fields: &[(ElementId, Value)]) -> Record {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Record {
            protocol: Protocol::Ipfix,
            sequence_number: 0,
            scope,
            elements: Arc::new(Elements::from(elements)),
            values,
        }
    }

    fn flow(src: [u8; 4], octets: u64) -> Record {
        record(
            Vec::new(),
            &[
                (iana::SOURCE_IPV4_ADDRESS, Value::Ipv4Address(src.into())),
                (iana::OCTET_DELTA_COUNT, Value::Unsigned64(octets)),
                (iana::PROTOCOL_IDENTIFIER, Value::Unsigned8(6)),
                (
                    iana::FLOW_START_MILLISECONDS,
                    Value::DateTimeMilliseconds(1_700_000_000_000),
                ),
            ],
        )
    }

    fn sampling_options(interval: u32) -> Record {
        record(
            vec![(
                Scope::Element(iana::OBSERVATION_DOMAIN_ID),
                Value::Unsigned32(DOMAIN),
            )],
            &[(iana::SAMPLING_PACKET_INTERVAL, Value::Unsigned32(interval))],
        )
    }

    fn set_ids(packet: &Packet) -> Vec<&'static str> {
        packet
            .sets
            .iter()
            .map(|set| match set {
                Set::Templates(_) => "templates",
                Set::OptionsTemplates(_) => "options templates",
                Set::Data(_) => "data",
                Set::OptionsData(_) => "options data",
                Set::Undecoded { .. } => "undecoded",
                Set::Unknown(_) => "unknown",
            })
            .collect()
    }

    /// `packet` as a collector reads it: written, parsed and converted.
    fn collected(parser: &mut ipfix::Parser, packet: &Packet) -> Vec<Record> {
        let mut buf = Vec::new();
        ipfix::write(packet, &mut buf).unwrap();
        let parsed = parser.parse(&buf).unwrap();
        let received = Received {
            exporter: SocketAddr::from(([192, 0, 2, 1], 4739)),
            time: None,
        };
        let mut records = Vec::new();
        convert::ipfix::Converter::default().convert(parsed, &received, &mut records);
        records
    }

    #[test]
    fn templates_go_once_before_the_data_and_not_again() {
        let mut exporter = Exporter::new(DOMAIN);
        let first = exporter.export(&[flow([10, 0, 0, 1], 100)], NOW).unwrap();
        assert_eq!(set_ids(&first), ["templates", "data"]);
        let second = exporter.export(&[flow([10, 0, 0, 2], 200)], at(1)).unwrap();
        assert_eq!(set_ids(&second), ["data"]);
        assert_eq!(first.header.sequence_number, 0);
        assert_eq!(second.header.sequence_number, 1);
        assert_eq!(second.header.export_time, 1);
        assert_eq!(second.header.observation_domain_id, DOMAIN);
    }

    #[test]
    fn records_come_back_through_a_collector_as_they_went() {
        let mut exporter = Exporter::new(DOMAIN);
        let sent = [
            sampling_options(100),
            flow([10, 0, 0, 1], 100),
            flow([10, 0, 0, 2], 200),
        ];
        let packet = exporter.export(&sent, at(1_700_000_000)).unwrap();
        let mut parser = ipfix::Parser::new(Registry::iana(), Duration::from_secs(60));
        let records = collected(&mut parser, &packet);

        assert_eq!(records.len(), sent.len());
        for (sent, received) in sent.iter().zip(&records) {
            assert_eq!(received.scope, sent.scope);
            for (element, value) in sent.iter() {
                assert_eq!(received.first(element), Some(value), "{element}");
            }
        }
        assert_eq!(
            records[1].first(iana::SAMPLING_PACKET_SPACE),
            Some(&Value::Unsigned32(99)),
            "the options applied to the flows after them"
        );

        let later = exporter
            .export(&[flow([10, 0, 0, 3], 300)], at(1_700_000_001))
            .unwrap();
        assert_eq!(set_ids(&later), ["data"]);
        let records = collected(&mut parser, &later);
        assert_eq!(records.len(), 1, "the parser kept the templates");
        assert_eq!(records[0].sequence_number, 3);
    }

    #[test]
    fn a_new_shape_brings_every_template_along() {
        let mut exporter = Exporter::new(DOMAIN);
        exporter.export(&[flow([10, 0, 0, 1], 100)], NOW).unwrap();
        let packet = exporter
            .export(&[flow([10, 0, 0, 2], 200), sampling_options(10)], at(1))
            .unwrap();
        assert_eq!(
            set_ids(&packet),
            ["templates", "options templates", "data", "options data"]
        );
        let Set::Templates(templates) = &packet.sets[0] else {
            unreachable!()
        };
        let Set::OptionsTemplates(options) = &packet.sets[1] else {
            unreachable!()
        };
        assert_eq!(templates[0].template_id, 256);
        assert_eq!(options[0].template_id, 257);
        assert_eq!(options[0].scope_fields.len(), 1);
        assert_eq!(exporter.templates().count(), 2);
    }

    #[test]
    fn templates_are_sent_again_after_the_refresh_interval() {
        let mut exporter = Exporter::new(DOMAIN).with_template_refresh(Duration::from_secs(30));
        exporter.export(&[flow([10, 0, 0, 1], 1)], NOW).unwrap();
        let before = exporter.export(&[flow([10, 0, 0, 1], 1)], at(29)).unwrap();
        assert_eq!(set_ids(&before), ["data"]);
        let after = exporter.export(&[flow([10, 0, 0, 1], 1)], at(30)).unwrap();
        assert_eq!(set_ids(&after), ["templates", "data"]);
        let next = exporter.export(&[flow([10, 0, 0, 1], 1)], at(31)).unwrap();
        assert_eq!(set_ids(&next), ["data"]);

        exporter.resend_templates();
        let asked = exporter.export(&[], at(32)).unwrap();
        assert_eq!(set_ids(&asked), ["templates"]);
    }

    #[test]
    fn fields_are_as_wide_as_their_values_or_variable_length() {
        let mut exporter = Exporter::new(DOMAIN);
        let record = record(
            Vec::new(),
            &[
                (iana::OCTET_DELTA_COUNT, Value::Unsigned32(1)),
                (iana::INTERFACE_NAME, Value::String("eth0".into())),
                (
                    iana::SOURCE_IPV6_ADDRESS,
                    Value::Ipv6Address([1; 16].into()),
                ),
                (ElementId::from((9, 1)), Value::OctetArray(vec![1, 2, 3])),
            ],
        );
        exporter.export(&[record], NOW).unwrap();
        let Some(TemplateRef::Data(template)) = exporter.templates().next() else {
            unreachable!()
        };
        let lengths: Vec<_> = template.fields.iter().map(|f| f.field_length).collect();
        assert_eq!(lengths, [4, VARIABLE_LENGTH, 16, VARIABLE_LENGTH]);
        assert_eq!(template.fields[3].enterprise_number, Some(9));
    }

    #[test]
    fn records_that_follow_one_another_in_one_shape_share_a_set() {
        let mut exporter = Exporter::new(DOMAIN);
        let other = record(
            Vec::new(),
            &[(
                iana::DESTINATION_IPV4_ADDRESS,
                Value::Ipv4Address(Ipv4Addr::LOCALHOST),
            )],
        );
        let packet = exporter
            .export(
                &[
                    flow([10, 0, 0, 1], 1),
                    flow([10, 0, 0, 2], 2),
                    other,
                    flow([10, 0, 0, 3], 3),
                ],
                NOW,
            )
            .unwrap();
        assert_eq!(set_ids(&packet), ["templates", "data", "data", "data"]);
        let Set::Data(first) = &packet.sets[1] else {
            unreachable!()
        };
        assert_eq!(first.records.len(), 2);
        assert_eq!(exporter.templates().count(), 2, "one template per shape");
    }

    #[test]
    fn a_scope_that_is_not_an_element_cannot_be_sent() {
        use crate::protocol::netflow_v9::ScopeType;

        let mut exporter = Exporter::new(DOMAIN);
        let record = record(
            vec![(Scope::Type(ScopeType::LineCard), Value::Unsigned32(1))],
            &[(iana::SAMPLING_PACKET_INTERVAL, Value::Unsigned32(1))],
        );
        assert_eq!(
            exporter.export(&[record], NOW),
            Err(ExportError::Scope(ScopeType::LineCard))
        );
    }
}
