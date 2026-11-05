//! What reading turns up, whatever a reader reads from.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;

use crate::convert::{Received, Record};
use crate::protocol::ParseError;
use crate::reader::{Collector, Reader};

/// What one read turned up.
#[derive(Debug)]
pub enum Read {
    /// A flow, or an options record with its scope.
    Record(Record),
    /// No datagram before a socket's read timeout.
    Timeout,
    /// A datagram that could not be parsed.
    Malformed {
        exporter: SocketAddr,
        error: ParseError,
    },
}

/// The flows of a reader: options records are kept for its `options` but
/// not yielded, and timeouts and malformed datagrams are read past.
pub struct Flows<R = Reader>(pub(crate) R);

impl<R> Flows<R> {
    pub fn reader(&self) -> &R {
        &self.0
    }
}

impl<R: Iterator<Item = io::Result<Record>>> Iterator for Flows<R> {
    type Item = io::Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .find(|record| !record.as_ref().is_ok_and(Record::is_options))
    }
}

/// A collector, and the records it collected that are not read yet: a
/// datagram may carry many.
pub(crate) struct Queue {
    pub(crate) collector: Collector,
    pending: VecDeque<Record>,
}

impl Queue {
    pub(crate) fn new(collector: Collector) -> Self {
        Self {
            collector,
            pending: VecDeque::new(),
        }
    }

    /// The next record collected, in the order the exporters sent them.
    pub(crate) fn pop(&mut self) -> Option<Read> {
        self.pending.pop_front().map(Read::Record)
    }

    /// Collects a datagram's records for [`Queue::pop`]; a datagram that
    /// does not parse is [`Read::Malformed`].
    pub(crate) fn collect(&mut self, received: Received, datagram: &[u8]) -> Option<Read> {
        let error = self
            .collector
            .collect(received, datagram, &mut self.pending)
            .err()?;
        Some(Read::Malformed {
            exporter: received.exporter,
            error,
        })
    }
}
