//! What reading turns up, whatever a reader reads from.

use std::io;
use std::net::SocketAddr;

use crate::convert::Record;
use crate::protocol::ParseError;
use crate::reader::Reader;

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
