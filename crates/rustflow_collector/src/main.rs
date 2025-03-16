use std::net::UdpSocket;

use rustflow_parser::netflow_v5;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:2055").expect("couldn't bind to address");

    loop {
        let mut buf = [0; 9000];
        let (amt, src) = socket.recv_from(&mut buf).expect("didn't receive data");

        println!("Received {} bytes from {}", amt, src);

        let (_, data) = netflow_v5::parse(&buf[..amt]).expect("TODO: panic message");

        println!("{:#?}", data);
    }
}
