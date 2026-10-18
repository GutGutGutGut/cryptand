use std::io::{self, Read, Write};

const MAGIC: &[u8; 4] = b"CRPT";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 10;
pub const MAX_PAYLOAD_SIZE: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Data = 1,
    Close = 2,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Close),
            _ => Err(ProtocolError::InvalidPacketType),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidPacketType,
    PayloadTooLarge,
    InvalidLength,
    InvalidClosePayload,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub packet_type: PacketType,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(packet_type: PacketType, payload: Vec<u8>) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge);
        }

        if packet_type == PacketType::Close && !payload.is_empty() {
            return Err(ProtocolError::InvalidClosePayload);
        }

        Ok(Self {
            packet_type,
            payload,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        // Revalidate even if the fields were modified after construction.
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge);
        }

        if self.packet_type == PacketType::Close && !self.payload.is_empty() {
            return Err(ProtocolError::InvalidClosePayload);
        }

        let length =
            u32::try_from(self.payload.len()).map_err(|_| ProtocolError::PayloadTooLarge)?;

        let mut output = Vec::with_capacity(HEADER_LEN + self.payload.len());

        output.extend_from_slice(MAGIC);
        output.push(VERSION);
        output.push(self.packet_type as u8);
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(&self.payload);

        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() < HEADER_LEN {
            return Err(ProtocolError::InvalidLength);
        }

        if &input[0..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        if input[4] != VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }

        let packet_type = PacketType::try_from(input[5])?;

        let length = u32::from_be_bytes([input[6], input[7], input[8], input[9]]) as usize;

        if length > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge);
        }

        if input.len() != HEADER_LEN + length {
            return Err(ProtocolError::InvalidLength);
        }

        Self::new(packet_type, input[HEADER_LEN..].to_vec())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut header = [0u8; HEADER_LEN];
        reader.read_exact(&mut header)?;

        if &header[0..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid protocol magic",
            ));
        }

        if header[4] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported protocol version",
            ));
        }

        let packet_type = PacketType::try_from(header[5])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid packet type"))?;

        let length = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;

        if length > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload exceeds maximum size",
            ));
        }

        if packet_type == PacketType::Close && length != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "close packet must have an empty payload",
            ));
        }

        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload)?;

        Ok(Self {
            packet_type,
            payload,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let encoded = self
            .encode()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid protocol frame"))?;

        writer.write_all(&encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_frame_round_trip() {
        let original = Frame::new(PacketType::Data, b"hello CRYPTAND".to_vec()).unwrap();

        let encoded = original.encode().unwrap();
        let decoded = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn close_frame_has_no_payload() {
        let frame = Frame::new(PacketType::Close, vec![]).unwrap();

        assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut bytes = Frame::new(PacketType::Data, vec![])
            .unwrap()
            .encode()
            .unwrap();

        bytes[0] = b'X';

        assert_eq!(Frame::decode(&bytes), Err(ProtocolError::InvalidMagic));
    }

    #[test]
    fn rejects_unknown_packet_type() {
        let mut bytes = Frame::new(PacketType::Data, vec![])
            .unwrap()
            .encode()
            .unwrap();

        bytes[5] = 255;

        assert_eq!(Frame::decode(&bytes), Err(ProtocolError::InvalidPacketType));
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut bytes = Frame::new(PacketType::Data, b"hello".to_vec())
            .unwrap()
            .encode()
            .unwrap();

        bytes.pop();

        assert_eq!(Frame::decode(&bytes), Err(ProtocolError::InvalidLength));
    }

    #[test]
    fn rejects_oversized_payload() {
        let mut bytes = Frame::new(PacketType::Data, vec![])
            .unwrap()
            .encode()
            .unwrap();

        bytes[6..10].copy_from_slice(&((MAX_PAYLOAD_SIZE as u32) + 1).to_be_bytes());

        assert_eq!(Frame::decode(&bytes), Err(ProtocolError::PayloadTooLarge));
    }

    #[test]
    fn rejects_payload_on_close_packet() {
        assert_eq!(
            Frame::new(PacketType::Close, vec![1]),
            Err(ProtocolError::InvalidClosePayload)
        );
    }

    #[test]
    fn stream_read_write_round_trip() {
        let original = Frame::new(PacketType::Data, b"stream test".to_vec()).unwrap();

        let mut stream = Vec::new();
        original.write_to(&mut stream).unwrap();

        let decoded = Frame::read_from(&mut stream.as_slice()).unwrap();

        assert_eq!(decoded, original);
    }
}
