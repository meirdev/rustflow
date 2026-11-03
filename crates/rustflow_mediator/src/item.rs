use std::net::IpAddr;

use rustflow_convert::Record;

/// What flows through a pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Record(Record),
    Control(Control),
}

/// What a Collecting Process knows besides records (RFC 6183 section
/// 5.1), in order with them: a withdrawal comes after the last record it
/// affects.
#[derive(Debug, Clone, PartialEq)]
pub enum Control {
    /// An exporter was heard from for the first time, or again after its
    /// session closed.
    SessionOpened { exporter: IpAddr },
    /// An exporter's transport session ended; its templates are no longer
    /// valid.
    SessionClosed { exporter: IpAddr },
    TemplateWithdrawn {
        exporter: IpAddr,
        domain: u32,
        template_id: u16,
    },
    /// An options data record, for processes that keep exporter state of
    /// their own. Conversion has already applied it to the records that
    /// follow.
    Options {
        exporter: IpAddr,
        domain: u32,
        record: Record,
    },
}
