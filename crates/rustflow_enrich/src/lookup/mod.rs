//! Index construction and matching; independent of file formats and application
//! models.
mod exact;
mod key;
mod prefix;
mod row;

pub use exact::ExactTable;
pub use key::{Key, KeyType, parse_prefix};
pub use prefix::PrefixTable;
pub use row::{Row, Schema};

pub trait Lookup: Send + Sync {
    fn lookup(&self, key: Key<'_>) -> Option<&Row>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
