use std::net::{SocketAddr, TcpStream};
use std::thread;

use cryptand::protocol::{Frame, PacketType};
use cryptand::transport::listener::{CryptandListener, handle_connection};

#[test]
fn tcp_client_sends_data_and_closes_connection() {
    let listener = CryptandListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();

    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let stream = listener.accept().unwrap();
        handle_connection(stream).unwrap();
    });

    let mut client = TcpStream::connect(addr).unwrap();

    let message = Frame::new(PacketType::Data, b"teste local do Cryptand".to_vec()).unwrap();
    message.write_to(&mut client).unwrap();

    let close = Frame::new(PacketType::Close, vec![]).unwrap();
    close.write_to(&mut client).unwrap();

    drop(client);
    server.join().unwrap();
}
