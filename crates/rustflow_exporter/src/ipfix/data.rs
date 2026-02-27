use byteorder::{NetworkEndian, WriteBytesExt};
use std::io::Write;
use std::net::Ipv4Addr;

use super::message::SetHeader;

#[derive(Debug, Clone)]
pub struct FlowData {
    pub source_ipv4: Ipv4Addr,
    pub destination_ipv4: Ipv4Addr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub octet_count: u64,
    pub packet_count: u64,
    pub tcp_flags: u16,
    pub forwarding_status: u32,
}

impl FlowData {
    pub fn encode(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Fields must be in the same order as template
        buffer.write_all(&self.source_ipv4.octets())?;
        buffer.write_all(&self.destination_ipv4.octets())?;
        buffer.write_u8(self.protocol)?;
        buffer.write_u16::<NetworkEndian>(self.source_port)?;
        buffer.write_u16::<NetworkEndian>(self.destination_port)?;
        buffer.write_u64::<NetworkEndian>(self.octet_count)?;
        buffer.write_u64::<NetworkEndian>(self.packet_count)?;
        buffer.write_u16::<NetworkEndian>(self.tcp_flags)?;
        buffer.write_u32::<NetworkEndian>(self.forwarding_status)?;

        Ok(buffer)
    }
}

#[derive(Debug)]
pub struct DataRecord {
    pub template_id: u16,
    pub records: Vec<FlowData>,
}

impl DataRecord {
    pub fn new(template_id: u16) -> Self {
        Self {
            template_id,
            records: Vec::new(),
        }
    }

    pub fn add_flow(&mut self, flow: FlowData) {
        self.records.push(flow);
    }

    pub fn encode_as_set(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Encode all flow records
        let mut records_data = Vec::new();
        for flow in &self.records {
            let flow_data = flow.encode()?;
            records_data.write_all(&flow_data)?;
        }

        // Set Header: 4 bytes (Set ID + Length) + records data
        let set_length = 4 + records_data.len() as u16;
        let set_header = SetHeader::new(self.template_id, set_length);

        set_header.encode(&mut buffer)?;
        buffer.write_all(&records_data)?;

        Ok(buffer)
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}

#[derive(Debug)]
pub struct OptionsDataRecord {
    pub template_id: u16,
    pub observation_domain_id: u32,
    pub sampling_packet_interval: u32,
}

impl OptionsDataRecord {
    pub fn new(
        template_id: u16,
        observation_domain_id: u32,
        sampling_packet_interval: u32,
    ) -> Self {
        Self {
            template_id,
            observation_domain_id,
            sampling_packet_interval,
        }
    }

    pub fn encode_as_set(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Encode the data record
        let mut record_data = Vec::new();
        record_data.write_u32::<NetworkEndian>(self.observation_domain_id)?;
        record_data.write_u32::<NetworkEndian>(self.sampling_packet_interval)?;

        // Set Header: 4 bytes (Set ID + Length) + record data
        let set_length = 4 + record_data.len() as u16;
        let set_header = SetHeader::new(self.template_id, set_length);

        set_header.encode(&mut buffer)?;
        buffer.write_all(&record_data)?;

        Ok(buffer)
    }
}
