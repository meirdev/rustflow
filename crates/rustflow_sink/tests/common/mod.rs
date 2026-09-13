#![allow(dead_code)]
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rustflow_core::common::common_flow::{CommonFlow, FlowType};

/// A `Write` that tests can read back after the encoder consumed it.
#[derive(Clone, Default)]
pub struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    pub fn boxed(&self) -> Box<dyn Write + Send> {
        Box::new(self.clone())
    }

    pub fn contents(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.contents()).unwrap()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn sample_flow() -> CommonFlow {
    let mut flow = CommonFlow::new(FlowType::Ipfix);
    flow.src_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
    flow.src_port = Some(443);
    flow.bytes = 1234;
    flow
}

/// 2024-01-02T15:07:00Z
pub const SAMPLE: i64 = 1_704_208_020;

pub fn stamp(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap()
}
