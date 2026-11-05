use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::Feed;

/// A Metering Process (RFC 5470 section 2): makes records of what it
/// observes, packets on an interface or nothing at all, and pushes them
/// into the pipeline as it goes. It runs on a thread of its own, from
/// the pipeline's start until it has nothing more to meter or is told to
/// stop.
pub trait Meter: Send {
    /// Pushes records through `feed` until there are no more, or `stop`
    /// is set. Returning drops the feed, which ends the stream for the
    /// components it feeds.
    fn run(self: Box<Self>, feed: Feed, stop: Stop) -> io::Result<()>;
}

/// Tells the meters to stop, once set.
#[derive(Debug, Clone, Default)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    pub fn set(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}
