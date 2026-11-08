//! Datagrams whose data sets came before their template, held until a
//! later datagram of their session brings it: RFC 3954 section 9 asks a
//! NetFlow v9 collector to, and RFC 7011 section 9 allows an IPFIX one to,
//! "for a short period of time".

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::convert::Received;

/// How much a collector holds of datagrams whose templates it does not
/// have yet; see
/// [`Collector::with_pending`](crate::reader::Collector::with_pending).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PendingLimits {
    /// Bytes held for one session, an exporter's transport address; past
    /// them, the session's oldest datagrams are dropped.
    pub session_bytes: usize,
    /// How long a datagram is held before it is dropped; zero holds
    /// nothing.
    pub max_age: Duration,
}

impl PendingLimits {
    pub fn new(session_bytes: usize, max_age: Duration) -> Self {
        Self {
            session_bytes,
            max_age,
        }
    }
}

/// What a collector holds, and what it had to drop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PendingStats {
    /// Original datagram sizes charged to the queue. A partially decoded
    /// datagram keeps its charge until all of its pending sets are released.
    pub held_bytes: usize,
    /// Datagrams dropped for a limit: evicted for newer ones, too large to
    /// hold, or held past their age.
    pub dropped_datagrams: u64,
}

/// The datagrams one session holds, oldest first.
pub(crate) struct Held<P> {
    datagrams: VecDeque<Deferred<P>>,
    bytes: usize,
}

/// Only the packet's undecoded sets remain, with the original receive time
/// for conversion and a monotonic arrival time for expiration.
pub(crate) struct Deferred<P> {
    pub(crate) received: Received,
    pub(crate) packet: P,
    bytes: usize,
    at: Instant,
}

impl<P> Deferred<P> {
    /// Gives the packet to `resolve`, which returns what of it is still to
    /// be held; that, with the charge and the age of the original.
    pub(crate) fn retry(self, resolve: impl FnOnce(P, &Received) -> Option<P>) -> Option<Self> {
        let packet = resolve(self.packet, &self.received)?;
        Some(Self { packet, ..self })
    }
}

impl<P> Default for Held<P> {
    fn default() -> Self {
        Self {
            datagrams: VecDeque::new(),
            bytes: 0,
        }
    }
}

impl<P> Held<P> {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.datagrams.len()
    }

    /// Holds a datagram, after dropping those held too long and, for
    /// room, the oldest; the number dropped.
    pub(crate) fn push(
        &mut self,
        limits: PendingLimits,
        received: Received,
        packet: P,
        bytes: usize,
    ) -> u64 {
        let now = Instant::now();
        let mut dropped = self.drop_aged(limits, now);
        if bytes > limits.session_bytes || limits.max_age.is_zero() {
            return dropped + 1;
        }
        while self.bytes > limits.session_bytes - bytes {
            self.pop_oldest();
            dropped += 1;
        }
        self.keep(Deferred {
            received,
            packet,
            bytes,
            at: now,
        });
        dropped
    }

    /// Holds again a datagram taken and still not decodable, with the
    /// charge and age it had: a retry does not make it younger.
    pub(crate) fn keep(&mut self, datagram: Deferred<P>) {
        self.bytes += datagram.bytes;
        self.datagrams.push_back(datagram);
    }

    /// Takes every datagram held, oldest first, dropping those held too
    /// long; the number dropped.
    pub(crate) fn take(&mut self, limits: PendingLimits) -> (Vec<Deferred<P>>, u64) {
        let dropped = self.drop_aged(limits, Instant::now());
        self.bytes = 0;
        let taken = self.datagrams.drain(..).collect();
        (taken, dropped)
    }

    fn drop_aged(&mut self, limits: PendingLimits, now: Instant) -> u64 {
        let mut dropped = 0;
        while self
            .datagrams
            .front()
            .is_some_and(|datagram| now.duration_since(datagram.at) >= limits.max_age)
        {
            self.pop_oldest();
            dropped += 1;
        }
        dropped
    }

    fn pop_oldest(&mut self) {
        if let Some(datagram) = self.datagrams.pop_front() {
            self.bytes -= datagram.bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn limits(session_bytes: usize, max_age: Duration) -> PendingLimits {
        PendingLimits {
            session_bytes,
            max_age,
        }
    }

    fn received() -> Received {
        Received {
            exporter: SocketAddr::from(([192, 0, 2, 1], 2055)),
            time: None,
        }
    }

    fn lengths(taken: &[Deferred<Vec<u8>>]) -> Vec<usize> {
        taken.iter().map(|datagram| datagram.packet.len()).collect()
    }

    #[test]
    fn datagrams_come_back_oldest_first() {
        let limits = limits(100, Duration::from_mins(1));
        let mut held = Held::default();
        assert_eq!(held.push(limits, received(), vec![0; 4], 4), 0);
        assert_eq!(held.push(limits, received(), vec![0; 6], 6), 0);
        assert_eq!(held.bytes(), 10);
        let (taken, dropped) = held.take(limits);
        assert_eq!((lengths(&taken), dropped), (vec![4, 6], 0));
        assert_eq!(held.bytes(), 0);
    }

    #[test]
    fn a_full_session_drops_its_oldest_datagrams() {
        let limits = limits(10, Duration::from_mins(1));
        let mut held = Held::default();
        held.push(limits, received(), vec![0; 6], 6);
        assert_eq!(held.push(limits, received(), vec![1; 6], 6), 1);
        assert_eq!(held.push(limits, received(), vec![0; 11], 11), 1);
        let (taken, _) = held.take(limits);
        assert_eq!(taken[0].packet, [1; 6]);
    }

    #[test]
    fn datagrams_held_past_their_age_are_dropped() {
        let limits = limits(100, Duration::from_secs(60));
        let mut held = Held::default();
        held.push(limits, received(), vec![0; 4], 4);
        held.datagrams[0].at = Instant::now() - limits.max_age;
        assert_eq!(held.push(limits, received(), vec![0; 5], 5), 1);
        held.datagrams[0].at = Instant::now() - limits.max_age;
        let (taken, dropped) = held.take(limits);
        assert_eq!((taken.len(), dropped), (0, 1));
        assert_eq!(held.bytes(), 0);
    }

    #[test]
    fn retrying_does_not_restart_a_datagrams_age() {
        let limits = limits(100, Duration::from_secs(60));
        let mut held = Held::default();
        held.push(limits, received(), (), 4);
        let arrived = Instant::now() - Duration::from_secs(30);
        held.datagrams[0].at = arrived;
        let (taken, dropped) = held.take(limits);
        assert_eq!(dropped, 0);
        for datagram in taken {
            held.keep(datagram);
        }
        assert_eq!(held.drop_aged(limits, arrived + limits.max_age), 1);
        assert_eq!(held.bytes(), 0);
    }

    #[test]
    fn zero_age_disables_holding() {
        let mut held = Held::default();
        assert_eq!(held.push(limits(100, Duration::ZERO), received(), (), 4), 1);
        assert_eq!(held.bytes(), 0);
    }
}
