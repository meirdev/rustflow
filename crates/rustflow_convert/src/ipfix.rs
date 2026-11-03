//! IPFIX data records, copied with their relative times made absolute.

use rustflow_protocol::ipfix::{Packet, Set};

use crate::domain::Domains;
use crate::templated::{Context, TimeBase, Uptime, convert_data};
use crate::{Protocol, Received, Record};

/// Converts one exporter's IPFIX messages, keeping what its options records
/// said of each observation domain, as a parser keeps its templates. Use
/// one converter per exporter address.
#[derive(Default)]
pub struct Converter {
    domains: Domains,
}

impl Converter {
    /// Converts a message's data records, adding them to `records`, after
    /// learning from its options records. A data record gets the sampling
    /// that options records gave for its observation domain, if any.
    ///
    /// Times relative to the export time (`flowStartDeltaMicroseconds`) are
    /// made absolute from it; uptimes (`flowStartSysUpTime`) from the
    /// exporter's `systemInitTimeMilliseconds`, once an options record gave
    /// it, and are kept as they are until then.
    pub fn convert(
        &mut self,
        packet: &Packet,
        received: &Received,
        records: &mut impl Extend<Record>,
    ) {
        let header = &packet.header;
        let domain_id = header.observation_domain_id;
        for set in &packet.sets {
            if let Set::OptionsData(data) = set {
                for record in data.records() {
                    self.domains.learn(domain_id, record);
                }
            }
        }

        let domain = self.domains.get(domain_id);
        let context = Context {
            protocol: Protocol::Ipfix,
            sequence_number: header.sequence_number,
            domain_id,
            received,
            time: TimeBase {
                export_time_ms: u64::from(header.export_time) * 1_000,
                uptime: Uptime::BootedAt(domain.and_then(|domain| domain.system_init_time_ms)),
            },
        };
        for set in &packet.sets {
            if let Set::Data(data) = set {
                convert_data(&context, domain, data, records);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use rustflow_protocol::DataSet;
    use rustflow_protocol::information_element::{ElementId, iana};
    use rustflow_protocol::ipfix::{self, FieldSpecifier, Header, OptionsTemplate, Template};
    use rustflow_protocol::value::Value;

    use super::*;

    const DOMAIN: u32 = 7;
    const EXPORT_TIME_MS: u64 = 1_700_000_000_000;

    fn field(element: ElementId) -> FieldSpecifier {
        FieldSpecifier {
            information_element_id: element.id,
            field_length: 4,
            enterprise_number: element.enterprise_number,
        }
    }

    fn data(fields: &[(ElementId, Value)]) -> Set {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Set::Data(DataSet {
            template: Arc::new(Template {
                template_id: 256,
                fields: elements.into_iter().map(field).collect(),
            }),
            records: vec![values],
        })
    }

    /// Options scoped to the observation domain.
    fn options(fields: &[(ElementId, Value)]) -> Set {
        let (elements, values): (Vec<_>, Vec<_>) = fields.iter().cloned().unzip();
        Set::OptionsData(DataSet {
            template: Arc::new(OptionsTemplate {
                template_id: 257,
                scope_fields: vec![field(iana::OBSERVATION_DOMAIN_ID)],
                option_fields: elements.into_iter().map(field).collect(),
            }),
            records: vec![[vec![Value::Unsigned32(DOMAIN)], values].concat()],
        })
    }

    fn converted(converter: &mut Converter, sets: Vec<Set>) -> Vec<Record> {
        let packet = Packet {
            header: Header {
                version: ipfix::VERSION,
                length: 0,
                export_time: 1_700_000_000,
                sequence_number: 42,
                observation_domain_id: DOMAIN,
            },
            sets,
        };
        let received = Received {
            exporter: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)),
            time: None,
        };
        let mut records = Vec::new();
        converter.convert(&packet, &received, &mut records);
        records
    }

    fn uptimes() -> Set {
        data(&[
            (iana::FLOW_START_SYS_UP_TIME, Value::Unsigned32(60_000)),
            (iana::FLOW_END_SYS_UP_TIME, Value::Unsigned32(61_000)),
        ])
    }

    #[test]
    fn uptimes_wait_for_the_exporters_init_time() {
        let mut converter = Converter::default();
        let before = converted(&mut converter, vec![uptimes()]);
        assert_eq!(
            before[0].first(iana::FLOW_START_SYS_UP_TIME),
            Some(&Value::Unsigned32(60_000))
        );
        assert_eq!(before[0].first(iana::FLOW_START_MILLISECONDS), None);

        let boot = options(&[(
            iana::SYSTEM_INIT_TIME_MILLISECONDS,
            Value::DateTimeMilliseconds(1_699_990_000_000),
        )]);
        let after = converted(&mut converter, vec![boot, uptimes()]);
        assert_eq!(
            after[0].first(iana::FLOW_START_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_699_990_060_000))
        );
        assert_eq!(
            after[0].first(iana::FLOW_END_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(1_699_990_061_000))
        );
        assert_eq!(after[0].first(iana::FLOW_START_SYS_UP_TIME), None);
    }

    #[test]
    fn times_before_the_export_time_are_made_absolute() {
        let records = converted(
            &mut Converter::default(),
            vec![data(&[
                (
                    iana::FLOW_START_DELTA_MICROSECONDS,
                    Value::Unsigned32(1_500_000),
                ),
                (iana::FLOW_END_DELTA_MICROSECONDS, Value::Unsigned32(250)),
            ])],
        );
        assert_eq!(
            records[0].first(iana::FLOW_START_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(EXPORT_TIME_MS - 1_500))
        );
        assert_eq!(
            records[0].first(iana::FLOW_END_MILLISECONDS),
            Some(&Value::DateTimeMilliseconds(EXPORT_TIME_MS - 1))
        );
    }

    #[test]
    fn records_get_their_selectors_sampling() {
        let selector = |id: u64, population: u32| {
            options(&[
                (iana::SELECTOR_ID, Value::Unsigned64(id)),
                (iana::SELECTOR_ALGORITHM, Value::Unsigned16(3)),
                (iana::SAMPLING_SIZE, Value::Unsigned32(1)),
                (iana::SAMPLING_POPULATION, Value::Unsigned32(population)),
            ])
        };
        let flow = |id: u64| {
            data(&[
                (iana::SELECTOR_ID, Value::Unsigned64(id)),
                (iana::OCTET_DELTA_COUNT, Value::Unsigned64(1)),
            ])
        };
        let records = converted(
            &mut Converter::default(),
            vec![selector(1, 100), selector(2, 1000), flow(2), flow(1)],
        );

        let populations: Vec<_> = records
            .iter()
            .map(|record| record.first(iana::SAMPLING_POPULATION).cloned())
            .collect();
        assert_eq!(
            populations,
            [Some(Value::Unsigned32(1000)), Some(Value::Unsigned32(100))]
        );
        assert_eq!(
            records[0].first(iana::SELECTOR_ALGORITHM),
            Some(&Value::Unsigned16(3))
        );
    }
}
