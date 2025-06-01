use std::net::UdpSocket;

use rustflow_parser::netflow_v9;
// use rustflow_parser::ipfix;

// use rustflow_parser::netflow_v5;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:8020").expect("couldn't bind to address");

    // let mut parser = ipfix::IPFIXParser::default();
    let mut parser = netflow_v9::parser::NetFlowV9Parser::default();

    loop {
        let mut buf = [0; 9000];
        let (amt, src) = socket.recv_from(&mut buf).expect("didn't receive data");

        println!("Received {} bytes from {}", amt, src);

        if let Ok((_, data)) = parser.parse(&buf[..amt]) {
            for record in data.flow_sets.iter() {
                println!("{:?}", record);
                match record {
                    netflow_v9::packet::FlowSet::Data(data_flow_set) => {
                        for data_record in &data_flow_set.records {
                            println!("Data Record: {:?}", serde_json::to_string(&data_record).unwrap());
                        }
                    }
                    netflow_v9::packet::FlowSet::Template(template_flow_set) => {
                        for template in &template_flow_set.records {
                            println!("Template ID: {}, Fields: {:?}", template.template_id, template.fields);
                            parser.register_template(data.header.source_id, template.template_id, template.clone());
                        }
                    }
                    netflow_v9::packet::FlowSet::OptionsTemplate(options_template_flow_set) => {
                        for template in &options_template_flow_set.records {
                            println!("Template ID: {}, Fields: {:?}", template.template_id, template.scope_fields);
                            parser.register_options_template(data.header.source_id, template.template_id, template.clone());
                        }
                    }
                }
            }
        } else {
            println!("No data parsed");
        }
    }
}
