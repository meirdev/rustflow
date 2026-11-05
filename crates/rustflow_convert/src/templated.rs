//! Data records of NetFlow v9 and IPFIX, whose fields are IANA elements
//! already: copied, with relative times made absolute and what conversion
//! adds appended.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::mem;
use std::sync::Arc;

use rustflow_protocol::information_element::{ElementId, iana};
use rustflow_protocol::netflow_v9::ScopeType;
use rustflow_protocol::value::Value;
use rustflow_protocol::{DataSet, Elements, ipfix, netflow_v9};

use crate::domain::Domain;
use crate::record::{Fields, Scope};
use crate::sampling::{Method, Sampling};
use crate::time::uptime_to_unix_millis;
use crate::{Protocol, Received, Record, packet_section};

/// Plans one converter may keep; the exporter decides how many templates
/// it names.
const MAX_PLANS: usize = 4096;

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
    /// The absolute element a relative time's values become, if they can
    /// be made absolute; `None` for any other element.
    fn absolute_element(&self, element: ElementId) -> Option<ElementId> {
        match element {
            iana::FLOW_START_SYS_UP_TIME => self
                .uptimes_convert()
                .then_some(iana::FLOW_START_MILLISECONDS),
            iana::FLOW_END_SYS_UP_TIME => self
                .uptimes_convert()
                .then_some(iana::FLOW_END_MILLISECONDS),
            iana::FLOW_START_DELTA_MICROSECONDS => Some(iana::FLOW_START_MILLISECONDS),
            iana::FLOW_END_DELTA_MICROSECONDS => Some(iana::FLOW_END_MILLISECONDS),
            _ => None,
        }
    }

    /// Makes a relative time's value absolute, giving the element it then
    /// is; any other element, or a value that cannot be made absolute, is
    /// left as it is.
    fn make_absolute(&self, element: ElementId, value: &mut Value) -> ElementId {
        match self.absolute_element(element) {
            Some(absolute) => match self.absolute_value(element, value) {
                Some(time) => {
                    *value = time;
                    absolute
                }
                None => element,
            },
            None => element,
        }
    }

    fn uptimes_convert(&self) -> bool {
        match self.uptime {
            Uptime::AtExport(_) => true,
            Uptime::BootedAt(boot_ms) => boot_ms.is_some(),
        }
    }

    /// The absolute time a value of `relative` stands for; `None` for a
    /// value that cannot be made absolute.
    fn absolute_value(&self, relative: ElementId, value: &Value) -> Option<Value> {
        let millis = match relative {
            iana::FLOW_START_SYS_UP_TIME | iana::FLOW_END_SYS_UP_TIME => self.uptime(value)?,
            iana::FLOW_START_DELTA_MICROSECONDS | iana::FLOW_END_DELTA_MICROSECONDS => {
                self.before_export(value)?
            }
            _ => return None,
        };
        Some(Value::DateTimeMilliseconds(millis))
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

/// The template of a data set: every value has an element.
pub(crate) trait DataTemplate: Elements {
    fn template_id(&self) -> u16;

    fn element_ids(&self) -> impl Iterator<Item = ElementId>;
}

impl DataTemplate for ipfix::Template {
    fn template_id(&self) -> u16 {
        self.template_id
    }

    fn element_ids(&self) -> impl Iterator<Item = ElementId> {
        self.fields.iter().map(|field| field.element_id())
    }
}

impl DataTemplate for netflow_v9::Template {
    fn template_id(&self) -> u16 {
        self.template_id
    }

    fn element_ids(&self) -> impl Iterator<Item = ElementId> {
        self.fields
            .iter()
            .map(|field| ElementId::iana(field.field_type))
    }
}

/// The template of an options data set: scope fields, then option fields.
pub(crate) trait OptionsTemplate: Elements {
    fn scope(&self) -> impl Iterator<Item = Scope>;

    fn option_element_ids(&self) -> impl Iterator<Item = ElementId>;
}

impl OptionsTemplate for ipfix::OptionsTemplate {
    fn scope(&self) -> impl Iterator<Item = Scope> {
        self.scope_fields
            .iter()
            .map(|field| Scope::Element(field.element_id()))
    }

    fn option_element_ids(&self) -> impl Iterator<Item = ElementId> {
        self.option_fields.iter().map(|field| field.element_id())
    }
}

impl OptionsTemplate for netflow_v9::OptionsTemplate {
    fn scope(&self) -> impl Iterator<Item = Scope> {
        self.scope_fields
            .iter()
            .map(|field| Scope::Type(ScopeType::from(field.field_type)))
    }

    fn option_element_ids(&self) -> impl Iterator<Item = ElementId> {
        self.option_fields
            .iter()
            .map(|field| ElementId::iana(field.field_type))
    }
}

/// Converts the records of an options data set, adding them to `records`
/// with their scope. They are few, so each is converted on its own.
pub(crate) fn convert_options<T: OptionsTemplate>(
    context: &Context,
    data: DataSet<T>,
    records: &mut impl Extend<Record>,
) {
    let base = Fields::additions(context.received, Some(context.domain_id));
    let mut last_elements = None;
    let template = &*data.template;
    let scope_len = template.scope().count();
    records.extend(data.records.into_iter().map(|mut values| {
        let mut option_values = values.split_off(scope_len.min(values.len()));
        let scope = template.scope().zip(values).collect();
        let mut elements = Vec::with_capacity(option_values.len() + base.elements.len());
        for (element, value) in template.option_element_ids().zip(&mut option_values) {
            elements.push(context.time.make_absolute(element, value));
        }
        let mut fields = Fields {
            elements,
            values: option_values,
        };
        fields.append(base.clone());
        let mut record = fields.into_record(
            context.protocol,
            context.sequence_number,
            &mut last_elements,
        );
        record.scope = scope;
        record
    }));
}

/// What converting a record of each template comes to, worked out once per
/// template rather than once per record, by observation domain and
/// template ID.
pub(crate) struct Plans<T> {
    by_template: HashMap<(u32, u16), Plan<T>>,
}

impl<T> Default for Plans<T> {
    fn default() -> Self {
        Self {
            by_template: HashMap::new(),
        }
    }
}

impl<T: DataTemplate> Plans<T> {
    /// The plan for `template`, made anew if it, the additions or what
    /// the time base can make absolute changed since.
    fn plan(
        &mut self,
        context: &Context,
        additions: &[ElementId],
        template: &Arc<T>,
    ) -> &mut Plan<T> {
        let key = (context.domain_id, template.template_id());
        if self.by_template.len() >= MAX_PLANS && !self.by_template.contains_key(&key) {
            self.by_template.clear();
        }
        match self.by_template.entry(key) {
            Entry::Occupied(mut entry) => {
                if !entry.get().fits(context, additions, template) {
                    entry.insert(Plan::new(context, additions, template));
                }
                entry.into_mut()
            }
            Entry::Vacant(entry) => entry.insert(Plan::new(context, additions, template)),
        }
    }
}

struct Plan<T> {
    template: Arc<T>,
    additions: Vec<ElementId>,
    uptimes_convert: bool,
    /// The template's elements, relative times named by their absolute
    /// element.
    own: Vec<ElementId>,
    times: Vec<RelativeTime>,
    /// The field naming the record's sampler.
    sampler: Option<usize>,
    /// Whether a record may carry a packet section, whose fields vary with
    /// its bytes.
    section: bool,
    /// The elements of a whole record, additions included, for each
    /// sampling shape, once a record of that shape was converted.
    shapes: [Option<Arc<[ElementId]>>; SHAPES],
}

struct RelativeTime {
    index: usize,
    relative: ElementId,
}

/// How many element lists sampling can end a record with: none, and one
/// per method, stated or not.
const SHAPES: usize = 4;

fn shape(sampling: Option<Sampling>) -> usize {
    match sampling.map(|sampling| sampling.method) {
        None => 0,
        Some(None) => 1,
        Some(Some(Method::Systematic)) => 2,
        Some(Some(Method::Random)) => 3,
    }
}

impl<T: DataTemplate> Plan<T> {
    fn new(context: &Context, additions: &[ElementId], template: &Arc<T>) -> Self {
        let mut own = Vec::new();
        let mut times = Vec::new();
        let mut sampler = None;
        let mut section = false;
        for (index, element) in template.element_ids().enumerate() {
            match context.time.absolute_element(element) {
                Some(absolute) => {
                    times.push(RelativeTime {
                        index,
                        relative: element,
                    });
                    own.push(absolute);
                }
                None => own.push(element),
            }
            match element {
                iana::SAMPLER_ID | iana::SELECTOR_ID => sampler = sampler.or(Some(index)),
                iana::DATA_LINK_FRAME_SECTION | iana::IP_HEADER_PACKET_SECTION => section = true,
                _ => {}
            }
        }
        Self {
            template: Arc::clone(template),
            additions: additions.to_vec(),
            uptimes_convert: context.time.uptimes_convert(),
            own,
            times,
            sampler,
            section,
            shapes: Default::default(),
        }
    }

    fn fits(&self, context: &Context, additions: &[ElementId], template: &Arc<T>) -> bool {
        Arc::ptr_eq(&self.template, template)
            && self.additions == additions
            && self.uptimes_convert == context.time.uptimes_convert()
    }

    fn elements(&mut self, sampling: Option<Sampling>) -> Arc<[ElementId]> {
        let Self {
            additions,
            own,
            shapes,
            ..
        } = self;
        Arc::clone(shapes[shape(sampling)].get_or_insert_with(|| {
            let mut elements = own.clone();
            elements.extend_from_slice(additions);
            if let Some(sampling) = sampling {
                sampling.for_each(|element, _| elements.push(element));
            }
            elements.into()
        }))
    }
}

/// Converts the records of a data set, adding them to `records`, each
/// keeping its values. A record carrying a packet section (RFC 5477) gets
/// the fields dissecting it yields, those it does not have already. Records
/// whose elements come out the same share them.
pub(crate) fn convert_data<T: DataTemplate>(
    context: &Context,
    domain: Option<&Domain>,
    plans: &mut Plans<T>,
    data: DataSet<T>,
    records: &mut impl Extend<Record>,
) {
    let base = Fields::additions(context.received, Some(context.domain_id));
    let plan = plans.plan(context, &base.elements, &data.template);
    let mut last_elements = None;
    records.extend(data.records.into_iter().map(|mut values| {
        let sampler_id = plan.sampler.and_then(|index| values.get(index)?.as_u64());
        let sampling = domain.and_then(|domain| domain.sampling_for(sampler_id));
        let mut all_absolute = true;
        for time in &plan.times {
            match values
                .get(time.index)
                .and_then(|value| context.time.absolute_value(time.relative, value))
            {
                Some(absolute) => values[time.index] = absolute,
                None => all_absolute = false,
            }
        }
        if all_absolute && !plan.section {
            values.extend(base.values.iter().cloned());
            if let Some(sampling) = sampling {
                sampling.for_each(|_, value| values.push(value));
            }
            return Record {
                protocol: context.protocol,
                sequence_number: context.sequence_number,
                scope: Vec::new(),
                elements: plan.elements(sampling),
                values,
            };
        }

        // A time that could not be made absolute keeps its element: it is
        // the one whose value is still relative.
        let mut elements = plan.own.clone();
        for time in &plan.times {
            if !matches!(values.get(time.index), Some(Value::DateTimeMilliseconds(_))) {
                elements[time.index] = time.relative;
            }
        }
        let mut fields = Fields { elements, values };
        if let Some((index, layer)) = packet_section::find(fields.iter()) {
            // The bytes are taken out while the fields they yield are added,
            // which may move the values.
            let section = mem::replace(&mut fields.values[index], Value::Null);
            if let Value::OctetArray(bytes) = &section {
                packet_section::dissect(layer, bytes, &mut |element, value| {
                    fields.add(element, value);
                });
            }
            fields.values[index] = section;
        }
        fields.append(base.clone());
        if let Some(sampling) = sampling {
            sampling.add_to(&mut fields);
        }
        fields.into_record(
            context.protocol,
            context.sequence_number,
            &mut last_elements,
        )
    }));
}
