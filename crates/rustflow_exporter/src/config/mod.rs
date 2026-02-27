use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub exporter: ExporterConfig,
    pub capture: CaptureConfig,
    pub flow: FlowConfig,
    pub template: TemplateConfig,
    pub options: OptionsConfig,
}

#[derive(Debug, Clone)]
pub struct ExporterConfig {
    pub collector_host: String,
    pub collector_port: u16,
    pub observation_domain_id: u32,
}

impl ExporterConfig {
    pub fn collector_addr(&self) -> anyhow::Result<SocketAddr> {
        let addr = format!("{}:{}", self.collector_host, self.collector_port);
        addr.parse()
            .map_err(|e| anyhow::anyhow!("Invalid collector address: {}", e))
    }
}

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: String,
    pub promiscuous: bool,
}

#[derive(Debug, Clone)]
pub struct FlowConfig {
    pub active_timeout: u64,   // seconds
    pub inactive_timeout: u64, // seconds
}

#[derive(Debug, Clone)]
pub struct TemplateConfig {
    pub refresh_rate: u64, // seconds
}

#[derive(Debug, Clone)]
pub struct OptionsConfig {
    pub sampling_packet_interval: u32,
}
