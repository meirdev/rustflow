//! Data records of NetFlow v9 and IPFIX, whose fields are IANA elements
//! already: copied, with relative times made absolute and what conversion
//! adds appended.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::convert::domains::{Domain, Domains, SAMPLING_KEYS, sampling_key};
use crate::convert::record::{Fields, Scope};
use crate::convert::sampling::{Method, Sampling};
use crate::convert::time::{TimeBase, Uptime};
use crate::convert::{Protocol, Received, Record, packet_fields};
use crate::protocol::information_element::{ElementId, iana};
use crate::protocol::netflow_v9::ScopeType;
use crate::protocol::value::Value;
use crate::protocol::{DataSet, ipfix, netflow_v9};

/// A packet of a protocol whose records templates describe: NetFlow v9 and
/// IPFIX.
pub trait Templated {
    type Data: DataTemplate;
    type Options: OptionsTemplate;

    const PROTOCOL: Protocol;

    /// What the header says of every record in the packet.
    fn header(&self) -> PacketHeader;

    /// The packet's data sets of each kind.
    fn into_sets(self) -> Sets<Self::Options, Self::Data>;
}

/// The data sets of a packet, by kind.
pub struct Sets<O, D> {
    pub options: Vec<DataSet<O>>,
    pub data: Vec<DataSet<D>>,
}

/// What a packet's header says of every record in it.
pub struct PacketHeader {
    pub sequence_number: u32,
    /// The observation domain ID, or the source ID in NetFlow v9.
    pub domain_id: u32,
    pub time: TimeBase,
}

/// Converts one exporter's packets of `P`, keeping what its options records
/// said of each observation domain, as a parser keeps its templates. Use
/// one converter per exporter address.
pub struct Converter<P> {
    domains: Domains,
    packets: PhantomData<P>,
}

impl<P> Default for Converter<P> {
    fn default() -> Self {
        Self {
            domains: Domains::default(),
            packets: PhantomData,
        }
    }
}

impl<P: Templated> Converter<P> {
    /// Converts a packet's records, adding them to `records`: its options
    /// records first, with their scope, then its data records, with the
    /// sampling the options records gave their observation domain, if any.
    ///
    /// Times relative to the export time (`flowStartDeltaMicroseconds`) are
    /// made absolute from it; uptimes (`flowStartSysUpTime`) from the
    /// exporter's uptime at export in NetFlow v9, and in IPFIX from its
    /// `systemInitTimeMilliseconds`, once an options record gave it, and
    /// are kept as they are until then.
    pub fn convert(&mut self, packet: P, received: &Received, records: &mut impl Extend<Record>) {
        let PacketHeader {
            sequence_number,
            domain_id,
            time,
        } = packet.header();
        let mut context = Context {
            protocol: P::PROTOCOL,
            sequence_number,
            domain_id,
            received,
            time,
        };
        let Sets { options, data } = packet.into_sets();
        for set in options {
            let domains = &mut self.domains;
            records.extend(
                convert_options(&context, set).inspect(|record| domains.learn(domain_id, record)),
            );
        }

        let domain = self.domains.get(domain_id);
        if let Uptime::BootedAt(boot_ms) = &mut context.time.uptime {
            *boot_ms = domain.and_then(|domain| domain.system_init_time_ms);
        }
        for set in data {
            convert_data(&context, domain, set, records);
        }
    }

    /// The latest options record of each kind the exporter sent, with its
    /// observation domain.
    pub fn options(&self) -> impl Iterator<Item = (u32, &Record)> {
        self.domains.options()
    }
}

/// What the records of one packet share.
pub(crate) struct Context<'a> {
    pub(crate) protocol: Protocol,
    pub(crate) sequence_number: u32,
    pub(crate) domain_id: u32,
    pub(crate) received: &'a Received,
    pub(crate) time: TimeBase,
}

/// The template of a data set: every value has an element.
pub trait DataTemplate {
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
pub trait OptionsTemplate {
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
            .map(|field| scope_element(ScopeType::from(field.field_type)))
    }

    fn option_element_ids(&self) -> impl Iterator<Item = ElementId> {
        self.option_fields
            .iter()
            .map(|field| ElementId::iana(field.field_type))
    }
}

/// The IPFIX element whose value a NetFlow v9 scope type gives (RFC 3954
/// section 6.1 names the types, RFC 7011 section 3.4.2.1 the elements): the
/// interface an Interface scope gives is taken as the one packets come in
/// on, the System as the Exporting Process, and the Cache as the Metering
/// Process filling it. An unassigned type has none.
fn scope_element(scope: ScopeType) -> Scope {
    let element = match scope {
        ScopeType::System => iana::EXPORTING_PROCESS_ID,
        ScopeType::Interface => iana::INGRESS_INTERFACE,
        ScopeType::LineCard => iana::LINE_CARD_ID,
        ScopeType::Cache => iana::METERING_PROCESS_ID,
        ScopeType::Template => iana::TEMPLATE_ID,
        ScopeType::Unassigned(_) => return Scope::Type(scope),
    };
    Scope::Element(element)
}

/// Converts the records of an options data set, each with its scope. They
/// are few, so each is converted on its own.
fn convert_options<'a, T: OptionsTemplate + 'a>(
    context: &'a Context,
    data: DataSet<T>,
) -> impl Iterator<Item = Record> + 'a {
    let template = data.template;
    let named: Vec<ElementId> = template
        .scope()
        .filter_map(|scope| match scope {
            Scope::Element(element) => Some(element),
            Scope::Type(_) => None,
        })
        .chain(template.option_element_ids())
        .collect();
    let base = Fields::additions(context.received, Some(context.domain_id)).lacking(&named);
    let mut last_elements = None;
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
    /// The fields that may key the record's sampling, by the element they
    /// key it as, in the order [`SAMPLING_KEYS`] tries them.
    sampling_keys: Vec<(ElementId, usize)>,
    /// Whether a record may carry a packet section, whose fields vary with
    /// its bytes.
    section: bool,
    /// The elements of a whole record, additions included, by sampling
    /// shape, built as records of that shape come.
    shapes: [Option<Arc<[ElementId]>>; SHAPES],
}

/// How many element lists sampling can end a record with: none, and one
/// per method, stated or not.
const SHAPES: usize = 4;

struct RelativeTime {
    index: usize,
    relative: ElementId,
}

/// Which element list sampling ends a record with.
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
        let elements: Vec<ElementId> = template.element_ids().collect();
        let mut own = Vec::with_capacity(elements.len());
        let mut times = Vec::new();
        for (index, &element) in elements.iter().enumerate() {
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
        }
        let position = |wanted: ElementId| {
            elements
                .iter()
                .position(|&element| sampling_key(element) == Some(wanted))
        };
        Self {
            own,
            times,
            sampling_keys: SAMPLING_KEYS
                .iter()
                .filter_map(|&key| Some((key, position(key)?)))
                .collect(),
            section: elements.iter().any(|&element| {
                matches!(
                    element,
                    iana::DATA_LINK_FRAME_SECTION | iana::IP_HEADER_PACKET_SECTION
                )
            }),
            shapes: Default::default(),
        }
    }

    fn elements(
        &mut self,
        additions: &[ElementId],
        sampling: Option<Sampling>,
    ) -> Arc<[ElementId]> {
        let Self { own, shapes, .. } = self;
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
fn convert_data<T: DataTemplate>(
    context: &Context,
    domain: Option<&Domain>,
    data: DataSet<T>,
    records: &mut impl Extend<Record>,
) {
    let mut layout = Layout::of(context, &*data.template);
    let base = Fields::additions(context.received, Some(context.domain_id)).lacking(&layout.own);
    let mut last_elements = None;
    records.extend(data.records.into_iter().map(|mut values| {
        let keys = layout
            .sampling_keys
            .iter()
            .filter_map(|&(key, index)| Some((key, values.get(index)?.as_u64()?)));
        let sampling = domain.and_then(|domain| domain.sampling_for(keys));
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
