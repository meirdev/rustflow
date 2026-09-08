use std::io;

use rustflow_core::common::common_flow::CommonFlow;
use serde::Serialize;

use super::{FlowEncoder, Output, RawEncoder};
use crate::flow::Enriched;

/// Decode and count flows but write nothing; the load-testing baseline.
pub struct Discard;

impl FlowEncoder for Discard {
    const EXTENSION: &'static str = "discard";

    fn open(_: Output, _: &[String]) -> io::Result<Self> {
        Ok(Self)
    }

    fn encode(&mut self, _: &CommonFlow, _: &Enriched) -> io::Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn finish(self) -> io::Result<()> {
        Ok(())
    }
}

/// `--format raw --serialization discard` stays allowed.
impl RawEncoder for Discard {
    fn write_value<T: Serialize + ?Sized>(&mut self, _: &T) -> io::Result<()> {
        Ok(())
    }
}
