use std::net::UdpSocket;

use rustflow_parser::netflow_v9;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:8020").expect("couldn't bind to address");

    let mut parser = netflow_v9::parser::NetFlowV9Parser::default();

    loop {
        let mut buf = [0; 9000];
        let (amt, src) = socket.recv_from(&mut buf).expect("didn't receive data");

        println!("Received {} bytes from {}", amt, src);

        match parser.parse(&buf[..amt]) {
            Ok(packet) => {
                parser.register_templates_from_packet(&packet);

                println!("{:?}", packet);
            }
            Err(err) => {
                println!("Error parsing data: {}", err);
            }
        }
    }
}
