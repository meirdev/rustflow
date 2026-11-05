//! Data sets that arrived before their template, held until a later
//! datagram brings it: RFC 3954 section 9 asks a NetFlow v9 collector to,
//! and RFC 7011 section 9 allows an IPFIX one to, "for a short period of
//! time".

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::convert::Received;

/// How much a collector holds of data sets whose template it does not have
/// yet; see [`Collector::with_pending`](crate::reader::Collector::with_pending).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingLimits {
    /// Bytes held for one session, an exporter's transport address; past
    /// them, the session's oldest sets are dropped.
    pub session_bytes: usize,
    /// Bytes held for all sessions together; past them, new sets are
    /// dropped.
    pub total_bytes: usize,
    /// How long a set is held before it is dropped.
    pub max_age: Duration,
}

/// What a collector holds, and what it had to drop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingStats {
    pub held_bytes: usize,
    /// Sets dropped for a limit: evicted for newer ones, refused, or held
    /// past their age.
    pub dropped_sets: u64,
}

/// The limits, and what every session holds together.
pub(crate) struct Budget {
    pub(crate) limits: PendingLimits,
    pub(crate) stats: PendingStats,
}

impl Budget {
    pub(crate) fn new(limits: PendingLimits) -> Self {
        Self {
            limits,
            stats: PendingStats::default(),
        }
    }
}

/// The sets one session holds of one protocol, oldest first, with the
/// header of the packet each came in.
pub(crate) struct Pending<H> {
    sets: VecDeque<Held<H>>,
    bytes: usize,
    datagrams: u64,
}

struct Held<H> {
    received: Received,
    header: H,
    /// Which datagram the set came in, to put the sets of one back
    /// together.
    datagram: u64,
    domain: u32,
    set_id: u16,
    body: Vec<u8>,
    at: Instant,
}

impl<H> Default for Pending<H> {
    fn default() -> Self {
        Self {
            sets: VecDeque::new(),
            bytes: 0,
            datagrams: 0,
        }
    }
}

impl<H: Clone> Pending<H> {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Holds the undecoded sets of one datagram, as (set ID, body), after
    /// dropping those held too long.
    pub(crate) fn hold(
        &mut self,
        budget: &mut Budget,
        received: Received,
        header: &H,
        domain: u32,
        sets: impl IntoIterator<Item = (u16, Vec<u8>)>,
    ) {
        let now = Instant::now();
        while self
            .sets
            .front()
            .is_some_and(|held| now.duration_since(held.at) >= budget.limits.max_age)
        {
            self.drop_oldest(budget);
        }

        self.datagrams += 1;
        for (set_id, body) in sets {
            let length = body.len();
            if length > budget.limits.session_bytes {
                budget.stats.dropped_sets += 1;
                continue;
            }
            while self.bytes + length > budget.limits.session_bytes {
                self.drop_oldest(budget);
            }
            if budget.stats.held_bytes + length > budget.limits.total_bytes {
                budget.stats.dropped_sets += 1;
                continue;
            }
            self.bytes += length;
            budget.stats.held_bytes += length;
            self.sets.push_back(Held {
                received,
                header: header.clone(),
                datagram: self.datagrams,
                domain,
                set_id,
                body,
                at: now,
            });
        }
    }

    /// The sets `decode` decodes now, put back together by the datagram
    /// they came in, oldest first; `decode` gives `None` for a set whose
    /// template is still unknown, which stays held.
    pub(crate) fn release<S>(
        &mut self,
        budget: &mut Budget,
        mut decode: impl FnMut(u32, u16, &[u8]) -> Option<S>,
    ) -> Vec<(Received, H, Vec<S>)> {
        let mut released: Vec<(Received, H, Vec<S>)> = Vec::new();
        let mut last_datagram = None;
        let mut kept = VecDeque::new();
        for held in self.sets.drain(..) {
            let Some(set) = decode(held.domain, held.set_id, &held.body) else {
                kept.push_back(held);
                continue;
            };
            self.bytes -= held.body.len();
            budget.stats.held_bytes -= held.body.len();
            match released.last_mut() {
                Some((_, _, sets)) if last_datagram == Some(held.datagram) => sets.push(set),
                _ => released.push((held.received, held.header, vec![set])),
            }
            last_datagram = Some(held.datagram);
        }
        self.sets = kept;
        released
    }

    fn drop_oldest(&mut self, budget: &mut Budget) {
        if let Some(held) = self.sets.pop_front() {
            self.bytes -= held.body.len();
            budget.stats.held_bytes -= held.body.len();
            budget.stats.dropped_sets += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn budget(session_bytes: usize, total_bytes: usize) -> Budget {
        Budget::new(PendingLimits {
            session_bytes,
            total_bytes,
            max_age: Duration::from_mins(1),
        })
    }

    fn received() -> Received {
        Received {
            exporter: SocketAddr::from(([192, 0, 2, 1], 2055)),
            time: None,
        }
    }

    fn hold(
        pending: &mut Pending<&'static str>,
        budget: &mut Budget,
        header: &'static str,
        sets: &[(u16, usize)],
    ) {
        let sets = sets.iter().map(|&(id, length)| (id, vec![0; length]));
        pending.hold(budget, received(), &header, 7, sets);
    }

    /// Releases the sets of `set_id`, as their lengths by datagram header.
    fn release(
        pending: &mut Pending<&'static str>,
        budget: &mut Budget,
        set_id: u16,
    ) -> Vec<(&'static str, Vec<usize>)> {
        pending
            .release(budget, |_, id, body| (id == set_id).then_some(body.len()))
            .into_iter()
            .map(|(_, header, sets)| (header, sets))
            .collect()
    }

    #[test]
    fn sets_come_back_by_datagram_once_they_decode() {
        let (mut pending, mut budget) = (Pending::default(), budget(100, 100));
        hold(
            &mut pending,
            &mut budget,
            "first",
            &[(256, 4), (257, 5), (256, 6)],
        );
        hold(&mut pending, &mut budget, "second", &[(256, 7)]);
        assert_eq!(budget.stats.held_bytes, 22);

        assert_eq!(
            release(&mut pending, &mut budget, 256),
            [("first", vec![4, 6]), ("second", vec![7])]
        );
        assert_eq!((pending.bytes(), budget.stats.held_bytes), (5, 5));
        assert_eq!(
            release(&mut pending, &mut budget, 257),
            [("first", vec![5])]
        );
        assert_eq!(budget.stats.held_bytes, 0);
    }

    #[test]
    fn a_full_session_drops_its_oldest_sets() {
        let (mut pending, mut budget) = (Pending::default(), budget(10, 100));
        hold(&mut pending, &mut budget, "old", &[(256, 6)]);
        hold(&mut pending, &mut budget, "new", &[(256, 6)]);
        hold(&mut pending, &mut budget, "too big", &[(256, 11)]);
        assert_eq!(release(&mut pending, &mut budget, 256), [("new", vec![6])]);
        assert_eq!(budget.stats.dropped_sets, 2);
    }

    #[test]
    fn a_full_budget_refuses_new_sets() {
        let mut budget = budget(10, 10);
        let (mut first, mut second) = (Pending::default(), Pending::default());
        hold(&mut first, &mut budget, "first", &[(256, 8)]);
        hold(&mut second, &mut budget, "second", &[(256, 4)]);
        assert_eq!(release(&mut second, &mut budget, 256), []);
        assert_eq!(release(&mut first, &mut budget, 256), [("first", vec![8])]);
        assert_eq!(budget.stats.dropped_sets, 1);
    }

    #[test]
    fn sets_held_past_their_age_are_dropped() {
        let mut budget = Budget::new(PendingLimits {
            session_bytes: 100,
            total_bytes: 100,
            max_age: Duration::ZERO,
        });
        let mut pending = Pending::default();
        hold(&mut pending, &mut budget, "old", &[(256, 4)]);
        hold(&mut pending, &mut budget, "new", &[(257, 4)]);
        assert_eq!(release(&mut pending, &mut budget, 256), []);
        assert_eq!(
            budget.stats,
            PendingStats {
                held_bytes: 4,
                dropped_sets: 1
            }
        );
    }
}
