use std::io;

use crate::Item;

/// Where items end up: IPFIX messages to another collector, files, or
/// anywhere else. Items are borrowed; an exporter copies what it keeps.
pub trait Exporter: Send {
    fn export(&mut self, items: &[Item]) -> io::Result<()>;

    /// Called on every tick, for exporters that buffer.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// The stream has ended; complete the output.
    fn finish(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}
