//! Records collected from datagrams but not read yet: a datagram may carry
//! many, and a reader hands them out one at a time.

use std::collections::VecDeque;

use crate::convert::{Received, Record};
use crate::reader::Collector;
use crate::reader::read::Read;

/// A collector, and the records it collected that are not read yet.
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
