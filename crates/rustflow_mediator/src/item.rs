use std::net::SocketAddr;

use rustflow_core_new::convert::Record;

/// What flows through a pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    /// A flow, or an options record with the scope it describes.
    Record(Record),
    Control(Control),
}

/// What a Collecting Process knows besides records (RFC 6183 section
/// 5.1), in order with them: a withdrawal comes after the last record it
/// affects. A transport session is identified by its exporter's transport
/// address, as the records are through `exporterTransportPort` and
/// `originalExporterIPv4Address` or its IPv6 form.
#[derive(Debug, Clone, PartialEq)]
pub enum Control {
    /// An exporter was heard from for the first time, or again after its
    /// session closed.
    SessionOpened { exporter: SocketAddr },
    /// An exporter's transport session ended; its templates are no longer
    /// valid.
    SessionClosed { exporter: SocketAddr },
    TemplateWithdrawn {
        exporter: SocketAddr,
        domain: u32,
        template_id: u16,
    },
}
