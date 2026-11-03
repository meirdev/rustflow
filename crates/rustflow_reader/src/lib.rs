//! A cursor for parsing big-endian binary protocols from a byte slice.
//!
//! A parser takes a `&mut Reader` and reads fields in wire order. Each read
//! either returns the value and moves past it, or fails and leaves the
//! reader where it was:
//!
//! ```
//! use rustflow_reader::{Reader, Truncated};
//!
//! #[derive(Debug, PartialEq)]
//! enum Error {
//!     Truncated(Truncated),
//!     SetLength(u16),
//! }
//!
//! impl From<Truncated> for Error {
//!     fn from(e: Truncated) -> Self {
//!         Self::Truncated(e)
//!     }
//! }
//!
//! struct Set {
//!     id: u16,
//!     values: Vec<u32>,
//! }
//!
//! fn parse_set(r: &mut Reader) -> Result<Set, Error> {
//!     let id = r.u16()?;
//!     let length = r.u16()?;
//!     let body_length = usize::from(length)
//!         .checked_sub(4)
//!         .ok_or(Error::SetLength(length))?;
//!     let mut body = r.sub(body_length)?;
//!     Ok(Set {
//!         id,
//!         values: body.many(Reader::u32),
//!     })
//! }
//!
//! let datagram = [0, 1, 0, 12, 0, 0, 0, 7, 0, 0, 0, 9];
//! let sets = Reader::new(&datagram).many(parse_set);
//! assert_eq!(sets[0].id, 1);
//! assert_eq!(sets[0].values, [7, 9]);
//! ```
//!
//! A [`Writer`] does the reverse, appending values to a byte vector.

use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub use writer::Writer;

mod writer;

/// A read needed more bytes than the reader had left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated {
    pub requested: usize,
    pub available: usize,
}

impl fmt::Display for Truncated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "needed {} bytes, {} left",
            self.requested, self.available
        )
    }
}

impl Error for Truncated {}

/// A position in a byte slice. Every read that fails leaves the reader
/// unchanged.
///
/// Copying a reader is free, so a parser can try something on a copy and
/// keep it only if it succeeds.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// The bytes not read yet.
    pub fn remaining(&self) -> &'a [u8] {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The next `n` bytes, borrowed from the underlying slice.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let (head, tail) = self.buf.split_at_checked(n).ok_or(Truncated {
            requested: n,
            available: self.buf.len(),
        })?;
        self.buf = tail;
        Ok(head)
    }

    /// The next `N` bytes as an array, for fields whose size the format
    /// fixes.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        let (head, tail) = self.buf.split_first_chunk().ok_or(Truncated {
            requested: N,
            available: self.buf.len(),
        })?;
        self.buf = tail;
        Ok(*head)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), Truncated> {
        self.bytes(n)?;
        Ok(())
    }

    /// A reader over the next `n` bytes, for a length-delimited block such
    /// as a set or a record. Whatever the block's parser leaves unread, such
    /// as padding, is still skipped here.
    pub fn sub(&mut self, n: usize) -> Result<Reader<'a>, Truncated> {
        self.bytes(n).map(Reader::new)
    }

    pub fn u8(&mut self) -> Result<u8, Truncated> {
        self.array().map(u8::from_be_bytes)
    }

    pub fn u16(&mut self) -> Result<u16, Truncated> {
        self.array().map(u16::from_be_bytes)
    }

    pub fn u32(&mut self) -> Result<u32, Truncated> {
        self.array().map(u32::from_be_bytes)
    }

    pub fn u64(&mut self) -> Result<u64, Truncated> {
        self.array().map(u64::from_be_bytes)
    }

    pub fn u128(&mut self) -> Result<u128, Truncated> {
        self.array().map(u128::from_be_bytes)
    }

    pub fn i8(&mut self) -> Result<i8, Truncated> {
        self.array().map(i8::from_be_bytes)
    }

    pub fn i16(&mut self) -> Result<i16, Truncated> {
        self.array().map(i16::from_be_bytes)
    }

    pub fn i32(&mut self) -> Result<i32, Truncated> {
        self.array().map(i32::from_be_bytes)
    }

    pub fn i64(&mut self) -> Result<i64, Truncated> {
        self.array().map(i64::from_be_bytes)
    }

    pub fn f32(&mut self) -> Result<f32, Truncated> {
        self.array().map(f32::from_be_bytes)
    }

    pub fn f64(&mut self) -> Result<f64, Truncated> {
        self.array().map(f64::from_be_bytes)
    }

    pub fn ipv4(&mut self) -> Result<Ipv4Addr, Truncated> {
        self.array().map(Ipv4Addr::from)
    }

    pub fn ipv6(&mut self) -> Result<Ipv6Addr, Truncated> {
        self.array().map(Ipv6Addr::from)
    }

    /// Runs `parse` until the reader is empty or `parse` fails, and returns
    /// what it parsed.
    ///
    /// A failed attempt is undone, so the reader stops at the start of the
    /// item that did not parse, such as the padding at the end of a set. An
    /// attempt that reads nothing also stops the loop, since it would
    /// repeat forever.
    pub fn many<T, E>(&mut self, mut parse: impl FnMut(&mut Self) -> Result<T, E>) -> Vec<T> {
        let mut items = Vec::new();
        while !self.is_empty() {
            let mut attempt = *self;
            match parse(&mut attempt) {
                Ok(item) if attempt.len() < self.len() => {
                    *self = attempt;
                    items.push(item);
                }
                _ => break,
            }
        }
        items
    }

    /// Runs `parse` exactly `n` times. If any run fails, returns its error
    /// and leaves the reader unchanged.
    pub fn repeat<T, E>(
        &mut self,
        n: usize,
        mut parse: impl FnMut(&mut Self) -> Result<T, E>,
    ) -> Result<Vec<T>, E> {
        let mut reader = *self;
        let items = (0..n)
            .map(|_| parse(&mut reader))
            .collect::<Result<_, _>>()?;
        *self = reader;
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_are_big_endian() {
        let bytes: Vec<u8> = (0x01..=0x1f).collect();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8(), Ok(0x01));
        assert_eq!(r.u16(), Ok(0x0203));
        assert_eq!(r.u32(), Ok(0x0405_0607));
        assert_eq!(r.u64(), Ok(0x0809_0a0b_0c0d_0e0f));
        assert_eq!(r.u128(), Ok(0x1011_1213_1415_1617_1819_1a1b_1c1d_1e1f));
        assert!(r.is_empty());

        let mut r = Reader::new(&[
            0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xfc,
        ]);
        assert_eq!(r.i8(), Ok(-1));
        assert_eq!(r.i16(), Ok(-2));
        assert_eq!(r.i32(), Ok(-3));
        assert_eq!(r.i64(), Ok(-4));
        assert!(r.is_empty());

        let mut r = Reader::new(&[0x3f, 0x80, 0, 0, 0xc0, 0x04, 0, 0, 0, 0, 0, 0]);
        assert_eq!(r.f32(), Ok(1.0));
        assert_eq!(r.f64(), Ok(-2.5));
        assert!(r.is_empty());
    }

    #[test]
    fn a_short_read_reports_its_size_and_leaves_the_reader_unchanged() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(
            r.u32(),
            Err(Truncated {
                requested: 4,
                available: 3
            })
        );
        assert_eq!(
            r.bytes(5),
            Err(Truncated {
                requested: 5,
                available: 3
            })
        );
        assert_eq!(r.remaining(), [1, 2, 3]);
        assert_eq!(
            Truncated {
                requested: 4,
                available: 3
            }
            .to_string(),
            "needed 4 bytes, 3 left"
        );
    }

    #[test]
    fn bytes_borrow_from_the_input_not_the_reader() {
        let input = [1, 2, 3, 4];
        let head = {
            let mut r = Reader::new(&input);
            r.skip(1).unwrap();
            r.bytes(2).unwrap()
        };
        assert_eq!(head, [2, 3]);
    }

    #[test]
    fn a_sub_reader_skips_whatever_it_leaves_unread() {
        let mut r = Reader::new(&[0, 7, 0xaa, 0xbb, 9]);
        let mut block = r.sub(4).unwrap();
        assert_eq!(block.u16(), Ok(7));
        assert_eq!(r.u8(), Ok(9));
        assert!(r.is_empty());
    }

    #[test]
    fn addresses() {
        let mut bytes = vec![192, 0, 2, 1];
        bytes.extend(Ipv6Addr::LOCALHOST.octets());
        let mut r = Reader::new(&bytes);
        assert_eq!(r.ipv4(), Ok(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(r.ipv6(), Ok(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn many_stops_at_the_first_item_that_does_not_parse() {
        let mut r = Reader::new(&[0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb]);
        assert_eq!(r.many(Reader::u32), [1, 2]);
        assert_eq!(r.remaining(), [0xaa, 0xbb]);
    }

    #[test]
    fn many_undoes_a_partly_read_item() {
        let pair = |r: &mut Reader| Ok::<_, Truncated>((r.u16()?, r.u16()?));
        let mut r = Reader::new(&[0, 1, 0, 2, 0, 3]);
        assert_eq!(r.many(pair), [(1, 2)]);
        assert_eq!(r.remaining(), [0, 3]);
    }

    #[test]
    fn many_stops_when_an_item_reads_nothing() {
        let mut r = Reader::new(&[1, 2]);
        assert!(r.many(|_| Ok::<_, Truncated>(())).is_empty());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn many_on_an_empty_reader_parses_nothing() {
        assert!(Reader::new(&[]).many(Reader::u8).is_empty());
    }

    #[test]
    fn repeat_parses_exactly_n_items() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.repeat(2, Reader::u8), Ok(vec![1, 2]));
        assert_eq!(r.remaining(), [3]);
        assert_eq!(r.repeat(0, Reader::u8), Ok(vec![]));
    }

    #[test]
    fn repeat_that_fails_leaves_the_reader_unchanged() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(
            r.repeat(4, Reader::u8),
            Err(Truncated {
                requested: 1,
                available: 0
            })
        );
        assert_eq!(r.remaining(), [1, 2, 3]);
    }
}
