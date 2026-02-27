use byteorder::{NetworkEndian, WriteBytesExt};
use std::io::Write;

use super::IPFIX_VERSION;

#[derive(Debug, Clone)]
pub struct IpfixHeader {
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
}

impl IpfixHeader {
    pub fn new(observation_domain_id: u32, sequence_number: u32) -> Self {
        Self {
            version: IPFIX_VERSION,
            length: 16, // Will be updated when encoding full message
            export_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            sequence_number,
            observation_domain_id,
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u16::<NetworkEndian>(self.version)?;
        writer.write_u16::<NetworkEndian>(self.length)?;
        writer.write_u32::<NetworkEndian>(self.export_time)?;
        writer.write_u32::<NetworkEndian>(self.sequence_number)?;
        writer.write_u32::<NetworkEndian>(self.observation_domain_id)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SetHeader {
    pub set_id: u16,
    pub length: u16,
}

impl SetHeader {
    pub fn new(set_id: u16, length: u16) -> Self {
        Self { set_id, length }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u16::<NetworkEndian>(self.set_id)?;
        writer.write_u16::<NetworkEndian>(self.length)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct IpfixMessage {
    pub header: IpfixHeader,
    pub sets: Vec<Vec<u8>>,
}

impl IpfixMessage {
    pub fn new(observation_domain_id: u32, sequence_number: u32) -> Self {
        Self {
            header: IpfixHeader::new(observation_domain_id, sequence_number),
            sets: Vec::new(),
        }
    }

    pub fn add_set(&mut self, set_data: Vec<u8>) {
        self.sets.push(set_data);
    }

    pub fn encode(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Calculate total length
        let mut total_length = 16u16; // Header size
        for set in &self.sets {
            total_length += set.len() as u16;
        }
        self.header.length = total_length;

        // Encode header
        self.header.encode(&mut buffer)?;

        // Encode all sets
        for set in &self.sets {
            buffer.write_all(set)?;
        }

        Ok(buffer)
    }
}
