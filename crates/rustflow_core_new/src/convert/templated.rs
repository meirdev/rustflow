//! Data records of NetFlow v9 and IPFIX, whose fields are IANA elements
//! already: copied, with relative times made absolute and what conversion
//! adds appended.

use std::sync::Arc;

use crate::convert::domains::Domain;
use crate::convert::record::{Fields, Scope};
use crate::convert::sampling::{Method, Sampling};
use crate::convert::time::TimeBase;
use crate::convert::{Protocol, Received, Record, packet_fields};
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::netflow_v9::ScopeType;
use crate::protocol::value::Value;
use crate::protocol::{DataSet, ipfix, netflow_v9};

/// What the records of one packet share.
pub(crate) struct Context<'a> {
    pub(crate) protocol: Protocol,
    pub(crate) sequence_number: u32,
    pub(crate) domain_id: u32,
    pub(crate) received: &'a Received,
    pub(crate) time: TimeBase,
}

/// The template of a data set: every value has an element.
pub(crate) trait DataTemplate {
    fn element_ids(&self) -> impl Iterator<Item = ElementId>;
}

impl DataTemplate for ipfix::Template {
    fn element_ids(&self) -> impl Iterator<Item = ElementId> {
        self.fields.iter().map(|field| field.element_id())
    }
}

impl DataTemplate for netflow_v9::Template {
    fn element_ids(&self) -> impl Iterator<Item = ElementId> {
        self.fields
            .iter()
            .map(|field| ElementId::iana(field.field_type))
    }
}

/// The template of an options data set: scope fields, then option fields.
pub(crate) trait OptionsTemplate {
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

/// Converts the records of an options data set, each with its scope. They
/// are few, so each is converted on its own.
pub(crate) fn convert_options<'a, T: OptionsTemplate + 'a>(
    context: &'a Context,
    data: DataSet<T>,
) -> impl Iterator<Item = Record> + 'a {
    let base = Fields::additions(context.received, Some(context.domain_id));
    let mut last_elements = None;
    let template = data.template;
    let scope_len = template.scope().count();
    data.records.into_iter().map(move |mut values| {
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
    })
}

/// What converting a record of a template comes to, worked out once per
/// data set rather than once per record.
struct Layout {
    /// The template's elements, relative times named by their absolute
    /// element.
    own: Vec<ElementId>,
    times: Vec<RelativeTime>,
    /// The field naming the record's sampler.
    sampler: Option<usize>,
    /// Whether a record may carry a packet section, whose fields vary with
    /// its bytes.
    section: bool,
    /// The elements of a whole record, additions included, by sampling
    /// shape, built as records of that shape come.
    shapes: Vec<(usize, Arc<[ElementId]>)>,
}

struct RelativeTime {
    index: usize,
    relative: ElementId,
}

/// Which element list sampling ends a record with: none, or one per
/// method, stated or not.
fn shape(sampling: Option<Sampling>) -> usize {
    match sampling.map(|sampling| sampling.method) {
        None => 0,
        Some(None) => 1,
        Some(Some(Method::Systematic)) => 2,
        Some(Some(Method::Random)) => 3,
    }
}

impl Layout {
    fn of(context: &Context, template: &impl DataTemplate) -> Self {
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
            own,
            times,
            sampler,
            section,
            shapes: Vec::new(),
        }
    }

    fn elements(
        &mut self,
        additions: &[ElementId],
        sampling: Option<Sampling>,
    ) -> Arc<[ElementId]> {
        let shape = shape(sampling);
        if let Some((_, elements)) = self.shapes.iter().find(|(known, _)| *known == shape) {
            return Arc::clone(elements);
        }
        let mut elements = self.own.clone();
        elements.extend_from_slice(additions);
        if let Some(sampling) = sampling {
            sampling.for_each(|element, _| elements.push(element));
        }
        let elements: Arc<[ElementId]> = elements.into();
        self.shapes.push((shape, Arc::clone(&elements)));
        elements
    }
}

/// Converts the records of a data set, adding them to `records`, each
/// keeping its values. A record carrying a packet section (RFC 5477) gets
/// the fields dissecting it yields, those it does not have already. Records
/// whose elements come out the same share them.
pub(crate) fn convert_data<T: DataTemplate>(
    context: &Context,
    domain: Option<&Domain>,
    data: DataSet<T>,
    records: &mut impl Extend<Record>,
) {
    let base = Fields::additions(context.received, Some(context.domain_id));
    let mut layout = Layout::of(context, &*data.template);
    let mut last_elements = None;
    records.extend(data.records.into_iter().map(|mut values| {
        let sampler_id = layout.sampler.and_then(|index| values.get(index)?.as_u64());
        let sampling = domain.and_then(|domain| domain.sampling_for(sampler_id));
        let mut all_absolute = true;
        for time in &layout.times {
            match values
                .get(time.index)
                .and_then(|value| context.time.absolute_value(time.relative, value))
            {
                Some(absolute) => values[time.index] = absolute,
                None => all_absolute = false,
            }
        }
        // Usually every time is made absolute and there is no packet
        // section, so a record's elements are the template's and the
        // additions: it reuses the list `layout` keeps for its sampling
        // shape and only appends values, instead of rebuilding its fields
        // and comparing element lists as the general path below does.
        if all_absolute && !layout.section {
            values.extend(base.values.iter().cloned());
            if let Some(sampling) = sampling {
                sampling.for_each(|_, value| values.push(value));
            }
            return Record {
                protocol: context.protocol,
                sequence_number: context.sequence_number,
                scope: Vec::new(),
                elements: layout.elements(&base.elements, sampling),
                values,
            };
        }

        // A time that could not be made absolute keeps its element: it is
        // the one whose value is still relative.
        let mut elements = layout.own.clone();
        for time in &layout.times {
            if !matches!(values.get(time.index), Some(Value::DateTimeMilliseconds(_))) {
                elements[time.index] = time.relative;
            }
        }
        let mut fields = Fields { elements, values };
        let headers = packet_fields::find(fields.iter()).and_then(|(index, layer)| {
            let Value::OctetArray(bytes) = &fields.values[index] else {
                return None;
            };
            packet_fields::headers(layer, bytes)
        });
        if let Some(headers) = headers {
            packet_fields::add(headers, &mut |element, value| fields.add(element, value));
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
