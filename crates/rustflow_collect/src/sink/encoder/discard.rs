use std::io;

use rustflow_core::common::common_flow::CommonFlow;

use super::{Encoder, Writer};
use crate::enrich::Enriched;

/// Writes nothing; the load-testing baseline.
pub struct Discard;

impl Discard {
    pub fn open(_: Writer, _: &[String]) -> io::Result<Self> {
        Ok(Self)
    }
}

impl Encoder for Discard {
    fn encode(&mut self, _: &CommonFlow, _: &Enriched) -> io::Result<()> {
        Ok(())
    }

    fn write_raw(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        Ok(())
    }
}
