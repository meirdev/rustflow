use std::net::IpAddr;

use crate::common::common_flow::{CommonFlow, FlowType};
use crate::common::convert::packet::{apply_ethernet_frame, apply_ip_packet};
use crate::sflow_v5::parser::{
    AsPathType, ExpandedFlowSample, ExtendedGateway, ExtendedRouter, ExtendedSwitch,
    FlowRecordType, FlowSample, HeaderProtocol, SFlowV5, SampledHeader, SampledIpv4, SampledIpv6,
};

pub struct SFlowV5Context<'a> {
    pub header: &'a SFlowV5,
}

impl SFlowV5Context<'_> {
    pub fn convert_flow_sample(&self, sample: &FlowSample) -> CommonFlow {
        let mut flow = CommonFlow::new(FlowType::SflowV5);
        flow.sequence_num = self.header.sequence_number;
        flow.sampler_address = Some(self.header.agent_address);
        flow.sampling_rate = Some(sample.sampling_rate);
        flow.in_if = Some(sample.input);
        flow.out_if = Some(sample.output);

        for record in &sample.records {
            self.apply_flow_record(&mut flow, &record.data);
        }

        flow
    }

    pub fn convert_expanded_flow_sample(&self, sample: &ExpandedFlowSample) -> CommonFlow {
        let mut flow = CommonFlow::new(FlowType::SflowV5);
        flow.sequence_num = self.header.sequence_number;
        flow.sampler_address = Some(self.header.agent_address);
        flow.sampling_rate = Some(sample.sampling_rate);
        flow.in_if = Some(sample.input_if_value);
        flow.out_if = Some(sample.output_if_value);

        for record in &sample.records {
            self.apply_flow_record(&mut flow, &record.data);
        }

        flow
    }

    fn apply_flow_record(&self, flow: &mut CommonFlow, record_type: &FlowRecordType) {
        match record_type {
            FlowRecordType::SampledHeader(header) => {
                self.apply_sampled_header(flow, header);
            }
            FlowRecordType::SampledIpv4(ipv4) => {
                self.apply_sampled_ipv4(flow, ipv4);
            }
            FlowRecordType::SampledIpv6(ipv6) => {
                self.apply_sampled_ipv6(flow, ipv6);
            }
            FlowRecordType::ExtendedRouter(router) => {
                self.apply_extended_router(flow, router);
            }
            FlowRecordType::ExtendedSwitch(switch) => {
                self.apply_extended_switch(flow, switch);
            }
            FlowRecordType::ExtendedGateway(gateway) => {
                self.apply_extended_gateway(flow, gateway);
            }
            _ => {}
        }
    }

    fn apply_sampled_header(&self, flow: &mut CommonFlow, header: &SampledHeader) {
        flow.bytes = header.frame_length as u64;
        flow.packets = 1;

        match header.protocol {
            HeaderProtocol::EthernetIso8023 => apply_ethernet_frame(flow, &header.header),
            HeaderProtocol::Ipv4 => {
                flow.etype = Some(0x0800);
                apply_ip_packet(flow, &header.header);
            }
            HeaderProtocol::Ipv6 => {
                flow.etype = Some(0x86dd);
                apply_ip_packet(flow, &header.header);
            }
            _ => {}
        }
    }

    fn apply_sampled_ipv4(&self, flow: &mut CommonFlow, ipv4: &SampledIpv4) {
        flow.src_addr = Some(IpAddr::V4(ipv4.src_ip));
        flow.dst_addr = Some(IpAddr::V4(ipv4.dst_ip));
        flow.etype = Some(0x0800);
        flow.proto = Some(ipv4.protocol as u8);
        flow.src_port = Some(ipv4.src_port as u16);
        flow.dst_port = Some(ipv4.dst_port as u16);
        flow.tcp_flags = Some(ipv4.tcp_flags as u16);
        flow.ip_tos = Some(ipv4.tos as u8);
        flow.bytes = ipv4.length as u64;
        flow.packets = 1;
    }

    fn apply_sampled_ipv6(&self, flow: &mut CommonFlow, ipv6: &SampledIpv6) {
        flow.src_addr = Some(IpAddr::V6(ipv6.src_ip));
        flow.dst_addr = Some(IpAddr::V6(ipv6.dst_ip));
        flow.etype = Some(0x86dd);
        flow.proto = Some(ipv6.protocol as u8);
        flow.src_port = Some(ipv6.src_port as u16);
        flow.dst_port = Some(ipv6.dst_port as u16);
        flow.tcp_flags = Some(ipv6.tcp_flags as u16);
        flow.bytes = ipv6.length as u64;
        flow.packets = 1;
    }

    fn apply_extended_router(&self, flow: &mut CommonFlow, router: &ExtendedRouter) {
        flow.next_hop = Some(router.nexthop);
        flow.src_net = Some(router.src_mask as u8);
        flow.dst_net = Some(router.dst_mask as u8);
    }

    fn apply_extended_switch(&self, flow: &mut CommonFlow, switch: &ExtendedSwitch) {
        flow.src_vlan = Some(switch.src_vlan as u16);
        flow.dst_vlan = Some(switch.dst_vlan as u16);
    }

    fn apply_extended_gateway(&self, flow: &mut CommonFlow, gateway: &ExtendedGateway) {
        flow.src_as = Some(gateway.src_as);
        flow.dst_as = match gateway.dst_as_path.last() {
            Some(AsPathType::AsSequence(as_seq)) => as_seq.last().copied(),
            _ => None,
        };
    }
}
