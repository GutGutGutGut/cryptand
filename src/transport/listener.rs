use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::protocol::{Frame, PacketType};

pub struct CryptandListener {
    listener: TcpListener,
}

impl CryptandListener {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener })
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn accept(&self) -> io::Result<TcpStream> {
        let (stream, _) = self.listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(Duration::from_secs(60)))?;
        Ok(stream)
    }
}

pub fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    loop {
        let frame = match Frame::read_from(&mut stream) {
            Ok(frame) => frame,
            Err(error)
                if error.kind() == io::ErrorKind::UnexpectedEof
                    || error.kind() == io::ErrorKind::ConnectionReset =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        match frame.packet_type {
            PacketType::Data => {
                // Temporário: apenas valida o recebimento do quadro.
                // Não imprime o conteúdo para evitar expor mensagens.
                eprintln!("Quadro de dados recebido: {} bytes", frame.payload.len());
            }
            PacketType::Close => return Ok(()),
        }
    }
}
