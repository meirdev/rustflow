use std::net::IpAddr;

use super::CommonFlow;
use crate::net::{self, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6, Protocol};

/// Steps through the headers, into tunnels, down to the innermost transport
/// header: the flow is of the innermost IP packet the octets reach, with
/// the MAC addresses and VLAN of the outer frame, the one sampled.
///
/// Every header that names a next one has taken octets, so the steps end.
pub(super) fn dissect(flow: &mut CommonFlow, mut protocol: Protocol, input: &mut &[u8]) {
    // Inside a tunnel, a frame is not the one sampled.
    let mut tunneled = false;
    loop {
        let next = match protocol {
            Protocol::Ethernet => {
                let ethernet = net::ethernet(input);
                if !tunneled {
                    flow.src_mac = ethernet.source();
                    flow.dst_mac = ethernet.destination();
                    flow.etype = ethernet.ethertype();
                }
                ethernet.protocol()
            }
            Protocol::Vlan => {
                let vlan = net::vlan(input);
                if !tunneled {
                    // The outermost tag, and the EtherType after the
                    // innermost.
                    flow.src_vlan = flow.src_vlan.or(vlan.vlan_identifier());
                    flow.etype = vlan.ethertype().or(flow.etype);
                }
                vlan.protocol()
            }
            Protocol::Ipv4 => {
                let ip = net::ipv4(input);
                flow.etype = Some(ETHER_TYPE_IPV4);
                flow.src_addr = ip.source().map(IpAddr::from);
                flow.dst_addr = ip.destination().map(IpAddr::from);
                flow.proto = ip.next_level_protocol();
                flow.ip_tos = ip.tos();
                flow.ip_ttl = ip.ttl();
                flow.fragment_id = ip.identification().map(u32::from);
                flow.fragment_offset = ip.fragment_offset();
                // An outer IPv6 header's, inside a tunnel.
                flow.ipv6_flow_label = None;
                ip.protocol()
            }
            Protocol::Ipv6 => {
                let ip = net::ipv6(input);
                flow.etype = Some(ETHER_TYPE_IPV6);
                flow.src_addr = ip.source().map(IpAddr::from);
                flow.dst_addr = ip.destination().map(IpAddr::from);
                // After the extension headers; unknown past a fragment.
                flow.proto = ip.protocol().and_then(Protocol::ip_protocol);
                flow.ip_tos = ip.traffic_class();
                flow.ip_ttl = ip.hop_limit();
                flow.ipv6_flow_label = ip.flow_label();
                // An outer IPv4 header's, inside a tunnel.
                flow.fragment_id = None;
                flow.fragment_offset = None;
                ip.protocol()
            }
            Protocol::Gre => {
                tunneled = true;
                net::gre(input).protocol()
            }
            Protocol::Vxlan => {
                tunneled = true;
                net::vxlan(input).protocol()
            }
            Protocol::Geneve => {
                tunneled = true;
                net::geneve(input).protocol()
            }
            Protocol::Mpls => {
                tunneled = true;
                net::mpls(input).protocol()
            }
            // A sampled packet is clipped, so its transport header may be
            // too; the parsers give what there is.
            Protocol::Udp => {
                let udp = net::udp(input);
                match udp.protocol() {
                    // The ports are the tunnel's; the inner packet's follow.
                    Some(tunnel @ (Protocol::Vxlan | Protocol::Geneve)) => Some(tunnel),
                    _ => {
                        flow.src_port = udp.source();
                        flow.dst_port = udp.destination();
                        return;
                    }
                }
            }
            Protocol::Tcp => {
                let tcp = net::tcp(input);
                flow.src_port = tcp.source();
                flow.dst_port = tcp.destination();
                flow.tcp_flags = tcp.flags().map(u16::from);
                return;
            }
            Protocol::Icmp | Protocol::Icmpv6 => {
                let icmp = net::icmp(input);
                flow.icmp_type = icmp.icmp_type();
                flow.icmp_code = icmp.icmp_code();
                return;
            }
            _ => return,
        };
        let Some(next) = next else {
            return;
        };
        protocol = next;
    }
}
