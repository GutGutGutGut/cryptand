
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct TorTransport {
    proxy_addr: SocketAddr,
    timeout: Duration,
}

impl TorTransport {
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn connect_proxy(&self) -> io::Result<TcpStream> {
        let stream =
            TcpStream::connect_timeout(&self.proxy_addr, self.timeout)?;

        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        Ok(stream)
    }

    pub fn connect_onion(&self, host: &str, port: u16) -> io::Result<TcpStream> {
       if !host.ends_with(".onion")
    || host.len() > 255
    || host.len() <= ".onion".len()
    || host.contains('\0')
      {
    return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "Endereço onion inválido",
    ));
      }

        let mut stream = self.connect_proxy()?;

        // SOCKS5: versão 5, um método oferecido, sem autenticação.
        stream.write_all(&[0x05, 0x01, 0x00])?;

        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting)?;

        if greeting != [0x05, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "O proxy não aceitou SOCKS5 sem autenticação",
            ));
        }

        // SOCKS5 CONNECT com endereço de domínio.
        let host_len = host.len() as u8;
        let [port_hi, port_lo] = port.to_be_bytes();

        let request = [
            &[0x05, 0x01, 0x00, 0x03, host_len][..],
            host.as_bytes(),
            &[port_hi, port_lo],
        ]
        .concat();

        stream.write_all(&request)?;

        let mut response = [0u8; 4];
        stream.read_exact(&mut response)?;

        if response[0] != 0x05 || response[1] != 0x00 || response[2] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Falha no CONNECT SOCKS5: código {}", response[1]),
            ));
        }

        // Consumir o endereço e a porta do endereço de retorno.
        let address_len = match response[3] {
            0x01 => 4,  // IPv4
            0x04 => 16, // IPv6
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len)?;
                len[0] as usize
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Tipo de endereço SOCKS5 desconhecido",
                ));
            }
        };

        let mut bound_address = vec![0u8; address_len + 2];
        stream.read_exact(&mut bound_address)?;

        Ok(stream)
    }
}
// C com memory safe é top!
