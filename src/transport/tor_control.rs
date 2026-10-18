use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

const SERVER_TO_CONTROLLER: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const CONTROLLER_TO_SERVER: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

const MAX_REPLY_LINE: usize = 8192;
const MAX_REPLY_LINES: usize = 64;

pub struct TorControl {
    addr: SocketAddr,
    cookie_path: PathBuf,
    timeout: Duration,
}

impl TorControl {
    pub fn new(addr: SocketAddr, cookie_path: PathBuf) -> Self {
        Self {
            addr,
            cookie_path,
            timeout: Duration::from_secs(5),
        }
    }

    fn connect(&self) -> io::Result<BufReader<TcpStream>> {
        let stream = TcpStream::connect_timeout(&self.addr, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(BufReader::new(stream))
    }

    /// Autentica o controlador com SAFECOOKIE.
    fn authenticated_connection(&self) -> io::Result<BufReader<TcpStream>> {
        let mut reader = self.connect()?;

        let cookie = fs::read(&self.cookie_path)?;
        if cookie.len() != 32 {
            return Err(invalid_data(
                "O cookie de autenticacao do Tor nao possui 32 bytes",
            ));
        }

        write_command(&mut reader, "PROTOCOLINFO 1")?;
        let reply = read_reply(&mut reader)?;

        if !reply
            .iter()
            .any(|line| line.starts_with("250-AUTH ") && line.contains("SAFECOOKIE"))
        {
            return Err(permission_denied("O Tor nao anunciou suporte a SAFECOOKIE"));
        }

        let mut client_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut client_nonce);

        write_command(
            &mut reader,
            &format!("AUTHCHALLENGE SAFECOOKIE {}", hex_encode(&client_nonce)),
        )?;

        let reply = read_reply(&mut reader)?;
        let challenge = reply
            .iter()
            .find(|line| line.starts_with("250 AUTHCHALLENGE "))
            .ok_or_else(|| invalid_data("Resposta AUTHCHALLENGE inesperada"))?;

        let server_hash = parse_hex_field(challenge, "SERVERHASH=")?;
        let server_nonce = parse_hex_field(challenge, "SERVERNONCE=")?;

        if server_hash.len() != 32 || server_nonce.len() != 32 {
            return Err(invalid_data("Tamanho invalido no desafio SAFECOOKIE"));
        }

        let mut message = Vec::with_capacity(96);
        message.extend_from_slice(&cookie);
        message.extend_from_slice(&client_nonce);
        message.extend_from_slice(&server_nonce);

        let expected_hash = hmac_sha256(SERVER_TO_CONTROLLER, &message);

        if !constant_time_eq(&server_hash, &expected_hash) {
            return Err(permission_denied(
                "A verificacao do servidor SAFECOOKIE falhou",
            ));
        }

        let client_hash = hmac_sha256(CONTROLLER_TO_SERVER, &message);
        write_command(
            &mut reader,
            &format!("AUTHENTICATE {}", hex_encode(&client_hash)),
        )?;
        expect_ok(&mut reader)?;

        Ok(reader)
    }

    /// Cria um servico onion v3 temporario.
    ///
    /// O Tor gera e mantem a chave privada. DiscardPK evita que
    /// a chave privada seja devolvida na resposta ADD_ONION.
    pub fn add_onion(&self, virtual_port: u16, target: SocketAddr) -> io::Result<String> {
        if virtual_port == 0 || target.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "As portas devem ser validas",
            ));
        }

        if !target.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "O destino onion deve ser loopback",
            ));
        }

        let mut reader = self.authenticated_connection()?;
        write_command(
            &mut reader,
            &format!(
                "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={},{}",
                virtual_port, target
            ),
        )?;

        let reply = read_reply(&mut reader)?;
        let service_id = reply
            .iter()
            .find_map(|line| line.strip_prefix("250-ServiceID="))
            .ok_or_else(|| invalid_data("Tor nao retornou ServiceID"))?;

        if !is_valid_v3_service_id(service_id) {
            return Err(invalid_data(
                "O Tor retornou um ServiceID onion v3 invalido",
            ));
        }

        Ok(format!("{service_id}.onion"))
    }

    /// Remove um servico pelo ServiceID, sem o sufixo .onion.
    pub fn del_onion(&self, service_id: &str) -> io::Result<()> {
        if !is_valid_v3_service_id(service_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ServiceID onion v3 invalido",
            ));
        }

        let mut reader = self.authenticated_connection()?;
        write_command(&mut reader, &format!("DEL_ONION {service_id}"))?;
        expect_ok(&mut reader)
    }

    /// Solicita o encerramento normal do Tor.
    pub fn signal_shutdown(&self) -> io::Result<()> {
        let mut reader = self.authenticated_connection()?;
        write_command(&mut reader, "SIGNAL SHUTDOWN")?;
        expect_ok(&mut reader)
    }
}

fn write_command(reader: &mut BufReader<TcpStream>, command: &str) -> io::Result<()> {
    if command.contains('\r') || command.contains('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Comando de controle contem quebra de linha",
        ));
    }

    let stream = reader.get_mut();
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

/// Le uma linha limitada sem perder dados ja armazenados no BufReader.
fn read_bounded_line(reader: &mut BufReader<TcpStream>, limit: usize) -> io::Result<String> {
    let mut bytes = Vec::with_capacity(128);

    loop {
        let (chunk, found_newline) = {
            let available = reader.fill_buf()?;

            if available.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Conexao encerrada durante resposta do ControlPort",
                ));
            }

            let newline = available.iter().position(|&byte| byte == b'\n');
            let count = newline.map_or(available.len(), |index| index + 1);

            if bytes.len() + count > limit {
                return Err(invalid_data("Linha do ControlPort muito longa"));
            }

            (available[..count].to_vec(), newline.is_some())
        };

        let count = chunk.len();
        bytes.extend_from_slice(&chunk);
        reader.consume(count);

        if found_newline {
            break;
        }
    }

    while bytes
        .last()
        .is_some_and(|&byte| byte == b'\n' || byte == b'\r')
    {
        bytes.pop();
    }

    String::from_utf8(bytes).map_err(|_| invalid_data("Resposta do ControlPort nao e UTF-8 valida"))
}

/// Le uma resposta Tor completa. Respostas de erro viram io::Error.
fn read_reply(reader: &mut BufReader<TcpStream>) -> io::Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut expected_code: Option<String> = None;

    loop {
        if lines.len() >= MAX_REPLY_LINES {
            return Err(invalid_data("Resposta do ControlPort tem linhas demais"));
        }

        let line = read_bounded_line(reader, MAX_REPLY_LINE)?;

        if line.len() < 4 || !line.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            return Err(invalid_data("Resposta malformada do ControlPort"));
        }

        let code = &line[..3];
        let separator = line.as_bytes()[3];

        if let Some(expected) = &expected_code {
            if code != expected {
                return Err(invalid_data("Codigo inconsistente na resposta Tor"));
            }
        } else {
            expected_code = Some(code.to_owned());
        }

        lines.push(line);

        match separator {
            b' ' => break,
            b'-' => continue,
            b'+' => {
                return Err(invalid_data("Resposta com bloco de dados nao suportada"));
            }
            _ => {
                return Err(invalid_data("Separador invalido na resposta Tor"));
            }
        }
    }

    if !lines.last().is_some_and(|line| line.starts_with("250 ")) {
        return Err(io::Error::other(format!(
            "Comando de controle rejeitado: {}",
            lines.join(" | ")
        )));
    }

    Ok(lines)
}

fn expect_ok(reader: &mut BufReader<TcpStream>) -> io::Result<()> {
    let reply = read_reply(reader)?;

    if reply.last().is_some_and(|line| line == "250 OK") {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Resposta inesperada do ControlPort: {}",
            reply.join(" | ")
        )))
    }
}

fn parse_hex_field(line: &str, field: &str) -> io::Result<Vec<u8>> {
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix(field))
        .ok_or_else(|| invalid_data("Campo ausente no desafio SAFECOOKIE"))?;

    hex_decode(value)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

fn hex_decode(value: &str) -> io::Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(invalid_data("Campo hexadecimal de tamanho impar"));
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid_data("Caractere hexadecimal invalido")),
    }
}

/// HMAC-SHA256 conforme RFC 2104.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut normalized = [0u8; 64];

    if key.len() > normalized.len() {
        let digest = Sha256::digest(key);
        normalized[..32].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];

    for index in 0..64 {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);

    let digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0u8;

    for (&a, &b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }

    difference == 0
}

fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;

    for byte in value.bytes() {
        let digit = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };

        buffer = (buffer << 5) | u32::from(digit);
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }

    // 56 caracteres Base32 representam exatamente 35 bytes.
    if bits != 0 || buffer != 0 {
        return None;
    }

    Some(output)
}

fn is_valid_v3_service_id(value: &str) -> bool {
    if value.len() != 56
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return false;
    }

    let decoded = match base32_decode(value) {
        Some(bytes) if bytes.len() == 35 => bytes,
        _ => return false,
    };

    let public_key = &decoded[..32];
    let checksum = &decoded[32..34];
    let version = decoded[34];

    if version != 3 {
        return false;
    }

    let mut input = b".onion checksum".to_vec();
    input.extend_from_slice(public_key);
    input.push(version);

    let digest = Sha3_256::digest(&input);
    checksum == &digest[..2]
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base32_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

        let mut output = String::new();
        let mut buffer: u32 = 0;
        let mut bits: u8 = 0;

        for &byte in bytes {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;

            while bits >= 5 {
                bits -= 5;
                output.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
                buffer &= (1u32 << bits) - 1;
            }
        }

        if bits > 0 {
            output.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
        }

        output
    }

    fn make_valid_service_id() -> String {
        let public_key = [0x42u8; 32];
        let version = 3u8;

        let mut input = b".onion checksum".to_vec();
        input.extend_from_slice(&public_key);
        input.push(version);

        let digest = Sha3_256::digest(&input);

        let mut bytes = Vec::with_capacity(35);
        bytes.extend_from_slice(&public_key);
        bytes.extend_from_slice(&digest[..2]);
        bytes.push(version);

        base32_encode(&bytes)
    }

    #[test]
    fn hmac_sha256_matches_known_vector() {
        // RFC 4231, caso de teste 1.
        let key = [0x0bu8; 20];
        let result = hmac_sha256(&key, b"Hi There");

        assert_eq!(
            hex_encode(&result),
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7"
                .replace(' ', "")
        );
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0x00, 0x12, 0xab, 0xff];
        let encoded = hex_encode(&bytes);

        assert_eq!(encoded, "0012abff");
        assert_eq!(hex_decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn accepts_valid_v3_service_id() {
        let service_id = make_valid_service_id();

        assert_eq!(service_id.len(), 56);
        assert!(is_valid_v3_service_id(&service_id));
    }

    #[test]
    fn rejects_invalid_service_ids() {
        assert!(!is_valid_v3_service_id("example.onion"));
        assert!(!is_valid_v3_service_id(&"a".repeat(56)));
        assert!(!is_valid_v3_service_id(&"b".repeat(56)));

        let mut invalid = make_valid_service_id().into_bytes();
        invalid[0] = if invalid[0] == b'a' { b'b' } else { b'a' };

        let invalid = String::from_utf8(invalid).unwrap();
        assert!(!is_valid_v3_service_id(&invalid));
    }

    #[test]
    fn constant_time_comparison_checks_equal_length_bytes() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
