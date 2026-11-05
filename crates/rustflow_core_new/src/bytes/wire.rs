use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bytes::{Reader, Truncated, Writer};

/// A value with one encoding on the wire: read it back from where it was
/// written. [`wire!`](crate::bytes::wire) implements it for a struct whose
/// fields follow each other on the wire in declaration order.
pub trait Wire: Sized {
    fn read(r: &mut Reader<'_>) -> Result<Self, Truncated>;

    fn write(&self, w: &mut Writer<'_>);
}

macro_rules! primitives {
    ($($ty:ty => $method:ident),* $(,)?) => {
        $(
            impl Wire for $ty {
                fn read(r: &mut Reader<'_>) -> Result<Self, Truncated> {
                    r.$method()
                }

                fn write(&self, w: &mut Writer<'_>) {
                    w.$method(*self);
                }
            }
        )*
    };
}

primitives! {
    u8 => u8,
    u16 => u16,
    u32 => u32,
    u64 => u64,
    u128 => u128,
    i8 => i8,
    i16 => i16,
    i32 => i32,
    i64 => i64,
    f32 => f32,
    f64 => f64,
    Ipv4Addr => ipv4,
    Ipv6Addr => ipv6,
}

/// Defines a struct whose fields lie on the wire one after another, in
/// declaration order, and implements [`Wire`] for it: reading fills the
/// fields in that order, writing emits them in that order. Every field's
/// type implements [`Wire`], so structs nest.
///
/// ```ignore
/// use crate::bytes::{Reader, Wire, Writer, wire};
///
/// wire! {
///     /// A counter and its interface.
///     #[derive(Debug, PartialEq)]
///     pub struct Octets {
///         pub if_index: u32,
///         pub octets: u64,
///     }
/// }
///
/// let value = Octets { if_index: 7, octets: 1 << 40 };
/// let mut buf = Vec::new();
/// value.write(&mut Writer::new(&mut buf));
/// assert_eq!(buf.len(), 12);
/// assert_eq!(Octets::read(&mut Reader::new(&buf)), Ok(value));
/// ```
macro_rules! wire {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_attr:meta])*
                $field_vis:vis $field:ident: $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$attr])*
        $vis struct $name {
            $(
                $(#[$field_attr])*
                $field_vis $field: $ty,
            )*
        }

        impl $crate::bytes::Wire for $name {
            fn read(r: &mut $crate::bytes::Reader<'_>) -> Result<Self, $crate::bytes::Truncated> {
                // Read ahead, so a struct cut short leaves the reader where
                // the struct began, as a single read does.
                let mut ahead = *r;
                let value = Self {
                    $($field: <$ty as $crate::bytes::Wire>::read(&mut ahead)?,)*
                };
                *r = ahead;
                Ok(value)
            }

            fn write(&self, w: &mut $crate::bytes::Writer<'_>) {
                $(<$ty as $crate::bytes::Wire>::write(&self.$field, w);)*
            }
        }
    };
}

pub(crate) use wire;

#[cfg(test)]
mod tests {
    use super::*;

    wire! {
        #[derive(Debug, Clone, PartialEq)]
        struct Inner {
            a: u16,
            b: Ipv4Addr,
        }
    }

    wire! {
        /// Nests another wire struct between primitives.
        #[derive(Debug, Clone, PartialEq)]
        pub(crate) struct Outer {
            /// First on the wire.
            pub(crate) first: u8,
            inner: Inner,
            last: i64,
        }
    }

    #[test]
    fn fields_round_trip_in_declaration_order() {
        let value = Outer {
            first: 1,
            inner: Inner {
                a: 0x0203,
                b: Ipv4Addr::new(10, 0, 0, 4),
            },
            last: -1,
        };
        let mut buf = Vec::new();
        value.write(&mut Writer::new(&mut buf));
        assert_eq!(
            buf,
            [1, 2, 3, 10, 0, 0, 4, 255, 255, 255, 255, 255, 255, 255, 255]
        );

        let mut r = Reader::new(&buf);
        assert_eq!(Outer::read(&mut r), Ok(value));
        assert!(r.is_empty());
    }

    #[test]
    fn a_truncated_struct_leaves_the_reader_where_the_struct_began() {
        let mut r = Reader::new(&[1, 2, 3, 10, 0, 0]);
        let before = r.len();
        assert!(Outer::read(&mut r).is_err());
        assert_eq!(r.len(), before);
    }
}
