use std::net::{Ipv4Addr, Ipv6Addr};

/// Appends big-endian values to a byte vector, the reverse of
/// [`Reader`](crate::Reader).
pub struct Writer<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> Writer<'a> {
    /// A writer appending to whatever `buf` already holds.
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }

    /// The length of the whole buffer, what it held before included.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Drops everything after the first `len` bytes, such as a packet that
    /// could not be written in full.
    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
    }

    /// Overwrites the two bytes at `at`, such as a length known only once
    /// what it counts is written.
    ///
    /// # Panics
    ///
    /// If the buffer holds fewer than `at + 2` bytes.
    pub fn set_u16(&mut self, at: usize, value: u16) {
        self.buf[at..at + 2].copy_from_slice(&value.to_be_bytes());
    }

    /// Overwrites the four bytes at `at`, such as a length known only once
    /// what it counts is written.
    ///
    /// # Panics
    ///
    /// If the buffer holds fewer than `at + 4` bytes.
    pub fn set_u32(&mut self, at: usize, value: u32) {
        self.buf[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// `n` zero bytes, such as padding.
    pub fn zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn u128(&mut self, value: u128) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn i8(&mut self, value: i8) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn i16(&mut self, value: i16) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn i32(&mut self, value: i32) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn i64(&mut self, value: i64) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn f32(&mut self, value: f32) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn f64(&mut self, value: f64) {
        self.bytes(&value.to_be_bytes());
    }

    pub fn ipv4(&mut self, address: Ipv4Addr) {
        self.bytes(&address.octets());
    }

    pub fn ipv6(&mut self, address: Ipv6Addr) {
        self.bytes(&address.octets());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Reader;

    #[test]
    fn values_are_appended_big_endian() {
        let mut buf = vec![0xaa];
        let mut w = Writer::new(&mut buf);
        w.u8(0x01);
        w.u16(0x0203);
        w.u32(0x0405_0607);
        w.zeros(2);
        w.bytes(&[0x08, 0x09]);
        assert_eq!(
            buf,
            [
                0xaa, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0, 0, 0x08, 0x09
            ]
        );
    }

    #[test]
    fn written_bytes_can_be_overwritten_and_dropped() {
        let mut buf = vec![0xaa];
        let mut w = Writer::new(&mut buf);
        let start = w.len();
        w.u16(0);
        w.u32(0x0102_0304);
        w.set_u16(start, 0xbeef);
        w.set_u32(start + 2, 0x0a0b_0c0d);
        assert_eq!(w.len(), 7);
        w.truncate(start + 2);
        assert!(!w.is_empty());
        assert_eq!(buf, [0xaa, 0xbe, 0xef]);
        let mut w = Writer::new(&mut buf);
        w.zeros(4);
        w.set_u32(3, 0x0102_0304);
        assert_eq!(buf, [0xaa, 0xbe, 0xef, 1, 2, 3, 4]);
    }

    #[test]
    fn a_reader_reads_back_what_was_written() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.u8(u8::MAX);
        w.u16(0x0102);
        w.u32(0x0304_0506);
        w.u64(0x0708_090a_0b0c_0d0e);
        w.u128(u128::MAX - 1);
        w.i8(-1);
        w.i16(-2);
        w.i32(-3);
        w.i64(-4);
        w.f32(1.0);
        w.f64(-2.5);
        w.ipv4(Ipv4Addr::new(192, 0, 2, 1));
        w.ipv6(Ipv6Addr::LOCALHOST);

        let mut r = Reader::new(&buf);
        assert_eq!(r.u8(), Ok(u8::MAX));
        assert_eq!(r.u16(), Ok(0x0102));
        assert_eq!(r.u32(), Ok(0x0304_0506));
        assert_eq!(r.u64(), Ok(0x0708_090a_0b0c_0d0e));
        assert_eq!(r.u128(), Ok(u128::MAX - 1));
        assert_eq!(r.i8(), Ok(-1));
        assert_eq!(r.i16(), Ok(-2));
        assert_eq!(r.i32(), Ok(-3));
        assert_eq!(r.i64(), Ok(-4));
        assert_eq!(r.f32(), Ok(1.0));
        assert_eq!(r.f64(), Ok(-2.5));
        assert_eq!(r.ipv4(), Ok(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(r.ipv6(), Ok(Ipv6Addr::LOCALHOST));
        assert!(r.is_empty());
    }
}
