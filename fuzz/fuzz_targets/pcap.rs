#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use rustflow_core::reader::{NetflowProcessor, PcapSource, Reader, SflowProcessor};

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = PcapSource::new(Cursor::new(data)) {
        let mut reader = Reader::new(source, NetflowProcessor::default());
        while let Ok(Some(_)) = reader.read_datagram() {}
    }
    if let Ok(source) = PcapSource::new(Cursor::new(data)) {
        let mut reader = Reader::new(source, SflowProcessor);
        while let Ok(Some(_)) = reader.read_datagram() {}
    }
});
