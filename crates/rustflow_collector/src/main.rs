use std::net::UdpSocket;

// use rustflow_parser::netflow_v9;
use rustflow_parser::ipfix;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:8020").expect("couldn't bind to address");

    let mut parser = ipfix::IPFIXParser::default();

    loop {
        let mut buf = [0; 9000];
        let (amt, src) = socket.recv_from(&mut buf).expect("didn't receive data");

        println!("Received {} bytes from {}", amt, src);

        if let Ok(data) = parser.parse(&buf[..amt]) {
            // println!("{:#?}", data);
            println!("{:?}", serde_json::to_string(&data.1).unwrap());
        } else {
            println!("No data parsed");
        }
    }
}
