use std::io;

use arrow_ipc::writer::StreamWriter;
use rustflow_core::common::common_flow::CommonFlow;

use super::columns::{BATCH_ROWS, Columns};
use super::{Encoder, Writer};
use crate::enrich::Enriched;

/// Apache ArrowIpc IPC streaming format. A record batch goes out on every
/// pipeline flush and whenever `BATCH_ROWS` accumulate, so a reader on
/// stdout sees flows as they arrive; the end-of-stream marker is written by
/// `finish`.
pub struct ArrowIpc {
    writer: StreamWriter<Writer>,
    columns: Columns,
    finished: bool,
}

impl ArrowIpc {
    pub fn open(out: Writer, enriched_fields: &[String]) -> io::Result<Self> {
        let columns = Columns::new(enriched_fields);
        let writer = StreamWriter::try_new(out, columns.schema()).map_err(io::Error::other)?;

        Ok(Self {
            writer,
            columns,
            finished: false,
        })
    }

    fn write_batch(&mut self) -> io::Result<()> {
        let rows = self.columns.rows();

        let Some(batch) = self.columns.take_batch()? else {
            return Ok(());
        };

        self.writer
            .write(&batch)
            .map_err(|e| io::Error::other(format!("batch of {rows} rows lost: {e}")))
    }

    fn end_stream(&mut self) -> io::Result<()> {
        self.finished = true;
        let written = self.write_batch();
        let ended = self.writer.finish().map_err(io::Error::other);
        written.and(ended)
    }
}

impl Drop for ArrowIpc {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.end_stream();
        }
    }
}

impl Encoder for ArrowIpc {
    fn encode(&mut self, flow: &CommonFlow, enriched: &Enriched) -> io::Result<()> {
        self.columns.append(flow, enriched);

        if self.columns.rows() >= BATCH_ROWS {
            self.write_batch()?;
        }

        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_batch()?;
        self.writer.flush().map_err(io::Error::other)
    }

    fn finish(&mut self) -> io::Result<()> {
        self.end_stream()
    }
}
