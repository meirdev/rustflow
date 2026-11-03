//! Big-endian reading and writing for binary protocols.
//!
//! A parser takes a `&mut Reader` and reads fields in wire order. Each read
//! either returns the value and moves past it, or fails and leaves the
//! reader where it was:
//!
//! ```
//! use rustflow_bytes::{Reader, Truncated};
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

pub use reader::{Reader, Truncated};
pub use writer::Writer;

mod reader;
mod writer;
