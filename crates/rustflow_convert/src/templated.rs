//! Data records of NetFlow v9 and IPFIX, whose fields are IANA elements
//! already: copied, with relative times made absolute and what conversion
//! adds appended.

use rustflow_protocol::information_element::{ElementId, iana};
use rustflow_protocol::value::Value;
use rustflow_protocol::{DataSet, Elements};

use crate::domain::Domain;
use crate::packet_section::{self, Section};
use crate::record::{Additions, shared};
use crate::time::uptime_to_unix_millis;
use crate::{Protocol, Received, Record};

/// What the records of one packet share.
pub(crate) struct Context<'a> {
    pub(crate) protocol: Protocol,
    pub(crate) sequence_number: u32,
    pub(crate) domain_id: u32,
    pub(crate) received: &'a Received,
    pub(crate) time: TimeBase,
}

/// What a packet's relative times are relative to.
pub(crate) struct TimeBase {
    pub(crate) export_time_ms: u64,
    pub(crate) uptime: Uptime,
}

/// What an exporter's uptime counts from.
pub(crate) enum Uptime {
    /// NetFlow v9: the uptime the header gives at the export time.
    AtExport(u32),
    /// IPFIX: the exporter's last (re)initialization, if an options record
    /// gave it.
    BootedAt(Option<u64>),
}

impl TimeBase {
    /// The absolute element and value a relative time stands for; `None`
    /// for any other element, or a time that cannot be made absolute.
    fn absolute(&self, element: ElementId, value: &Value) -> Option<(ElementId, Value)> {
        let (absolute, millis) = match element {
            iana::FLOW_START_SYS_UP_TIME => (iana::FLOW_START_MILLISECONDS, self.uptime(value)?),
            iana::FLOW_END_SYS_UP_TIME => (iana::FLOW_END_MILLISECONDS, self.uptime(value)?),
            iana::FLOW_START_DELTA_MICROSECONDS => {
                (iana::FLOW_START_MILLISECONDS, self.before_export(value)?)
            }
            iana::FLOW_END_DELTA_MICROSECONDS => {
                (iana::FLOW_END_MILLISECONDS, self.before_export(value)?)
            }
            _ => return None,
        };
        Some((absolute, Value::DateTimeMilliseconds(millis)))
    }

    fn uptime(&self, value: &Value) -> Option<u64> {
        let uptime_ms = value.as_u64()?;
        match self.uptime {
            Uptime::AtExport(sys_uptime_ms) => uptime_to_unix_millis(
                self.export_time_ms,
                sys_uptime_ms,
                u32::try_from(uptime_ms).ok()?,
            ),
            Uptime::BootedAt(boot_ms) => boot_ms?.checked_add(uptime_ms),
        }
    }

    /// A time given as microseconds before the export time.
    fn before_export(&self, value: &Value) -> Option<u64> {
        let export_time_us = self.export_time_ms.checked_mul(1_000)?;
        Some(export_time_us.checked_sub(value.as_u64()?)? / 1_000)
    }
}

/// Converts the records of a data set, adding them to `records`. A record
/// carrying a packet section (RFC 5477) gets the fields dissecting it
/// yields, those it does not have already. Records whose elements come out
/// the same share them.
pub(crate) fn convert_data<T: Elements>(
    context: &Context,
    domain: Option<&Domain>,
    data: &DataSet<T>,
    records: &mut impl Extend<Record>,
) {
    let base = Additions::new(context.received, Some(context.domain_id));
    let mut last_elements = None;
    records.extend(data.records().map(|record| {
        let mut additions = base.clone();
        if let Some(sampling) = domain.and_then(|domain| domain.sampling(record)) {
            sampling.add_to(&mut additions);
        }

        let mut elements = Vec::with_capacity(record.values.len() + additions.elements.len());
        let mut values = Vec::with_capacity(elements.capacity());
        for (element, value) in record.iter() {
            let Some(element) = element else {
                continue;
            };
            let (element, value) = context
                .time
                .absolute(element, value)
                .unwrap_or_else(|| (element, value.clone()));
            elements.push(element);
            values.push(value);
        }
        let own = record
            .iter()
            .filter_map(|(element, value)| Some((element?, value)));
        if let Some(section) = Section::of_record(own) {
            packet_section::dissect(section, &mut |element, value| {
                if !elements.contains(&element) {
                    elements.push(element);
                    values.push(value);
                }
            });
        }
        elements.extend(additions.elements);
        values.extend(additions.values);

        Record {
            protocol: context.protocol,
            sequence_number: context.sequence_number,
            elements: shared(&mut last_elements, elements),
            values,
        }
    }));
}
