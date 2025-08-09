use crate::error::{HtxError, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Frame types as defined in the HTX specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Stream data frame
    Stream = 0,
    /// Ping frame for keepalive
    Ping = 1,
    /// Connection close frame
    Close = 2,
    /// Key update frame
    KeyUpdate = 3,
    /// Flow control window update frame
    WindowUpdate = 4,
    /// Handshake frame for Noise protocol exchange
    Handshake = 5,
}

impl TryFrom<u8> for FrameType {
    type Error = HtxError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(FrameType::Stream),
            1 => Ok(FrameType::Ping),
            2 => Ok(FrameType::Close),
            3 => Ok(FrameType::KeyUpdate),
            4 => Ok(FrameType::WindowUpdate),
            5 => Ok(FrameType::Handshake),
            _ => Err(HtxError::InvalidFrame(value)),
        }
    }
}

/// Inner HTX frame structure
///
/// ```text
/// struct Frame {
///   uint24  length;     // ciphertext length (excl. tag)
///   uint8   type;       // 0=STREAM, 1=PING, 2=CLOSE, 3=KEY_UPDATE, 4=WINDOW_UPDATE, 5=HANDSHAKE
///   varint  stream_id;  // present if type==STREAM or type==WINDOW_UPDATE
///   uint8[] ciphertext;
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Frame {
    /// Frame type
    pub frame_type: FrameType,
    /// Stream ID (for STREAM and WINDOW_UPDATE frames)
    pub stream_id: Option<u64>,
    /// Frame payload (encrypted)
    pub payload: Bytes,
}

impl Frame {
    /// Create a new stream data frame
    pub fn stream(stream_id: u64, data: Bytes) -> Self {
        Self {
            frame_type: FrameType::Stream,
            stream_id: Some(stream_id),
            payload: data,
        }
    }

    /// Create a new ping frame
    pub fn ping(data: Bytes) -> Self {
        Self {
            frame_type: FrameType::Ping,
            stream_id: None,
            payload: data,
        }
    }

    /// Create a new close frame
    pub fn close(reason: &str) -> Self {
        Self {
            frame_type: FrameType::Close,
            stream_id: None,
            payload: Bytes::from(reason.as_bytes().to_vec()),
        }
    }

    /// Create a new key update frame
    pub fn key_update() -> Self {
        Self {
            frame_type: FrameType::KeyUpdate,
            stream_id: None,
            payload: Bytes::new(),
        }
    }

    /// Create a new handshake frame
    pub fn handshake(data: Bytes) -> Self {
        Self {
            frame_type: FrameType::Handshake,
            stream_id: None,
            payload: data,
        }
    }

    /// Create a new window update frame
    pub fn window_update(stream_id: u64, increment: u32) -> Self {
        let mut payload = BytesMut::with_capacity(4);
        payload.put_u32(increment);

        Self {
            frame_type: FrameType::WindowUpdate,
            stream_id: Some(stream_id),
            payload: payload.freeze(),
        }
    }

    /// Get the frame length (excluding the frame header)
    pub fn payload_len(&self) -> u32 {
        self.payload.len() as u32
    }

    /// Check if this frame requires a stream ID
    pub fn requires_stream_id(&self) -> bool {
        matches!(self.frame_type, FrameType::Stream | FrameType::WindowUpdate)
    }

    /// Serialize the frame header (without encryption)
    pub fn serialize_header(&self) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(16); // Conservative estimate

        // Length (24-bit big-endian)
        let length = self.payload_len();
        if length > 0xFFFFFF {
            return Err(HtxError::Protocol("Frame too large".to_string()));
        }

        buf.put_u8(((length >> 16) & 0xFF) as u8);
        buf.put_u8(((length >> 8) & 0xFF) as u8);
        buf.put_u8((length & 0xFF) as u8);

        // Type
        buf.put_u8(self.frame_type as u8);

        // Stream ID (varint) if present
        if let Some(stream_id) = self.stream_id {
            encode_varint(&mut buf, stream_id)?;
        } else if self.requires_stream_id() {
            return Err(HtxError::Protocol(
                "Stream ID required but not provided".to_string(),
            ));
        }

        Ok(buf.freeze())
    }

    /// Deserialize a frame from bytes
    pub fn deserialize(mut buf: Bytes) -> Result<Self> {
        if buf.len() < 4 {
            return Err(HtxError::Protocol("Frame too short".to_string()));
        }

        // Parse length (24-bit big-endian)
        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        buf.advance(3);

        // Parse type
        let frame_type = FrameType::try_from(buf[0])?;
        buf.advance(1);

        // Parse stream ID if required
        let stream_id = if matches!(frame_type, FrameType::Stream | FrameType::WindowUpdate) {
            Some(decode_varint(&mut buf)?)
        } else {
            None
        };

        // Validate length
        if buf.len() != length as usize {
            return Err(HtxError::Protocol(format!(
                "Frame length mismatch: expected {}, got {}",
                length,
                buf.len()
            )));
        }

        Ok(Self {
            frame_type,
            stream_id,
            payload: buf,
        })
    }
}

/// Frame codec for tokio streams
pub struct FrameCodec;

impl Encoder<Frame> for FrameCodec {
    type Error = HtxError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<()> {
        let header = frame.serialize_header()?;
        dst.reserve(header.len() + frame.payload.len());
        dst.put_slice(&header);
        dst.put_slice(&frame.payload);
        Ok(())
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = HtxError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 4 {
            return Ok(None); // Need more data
        }

        // Peek at the length
        let length = ((src[0] as u32) << 16) | ((src[1] as u32) << 8) | (src[2] as u32);

        // Check if we have enough data for the complete frame
        let header_size = estimate_header_size(&src[3])?;
        let total_size = 4 + header_size + length as usize;

        if src.len() < total_size {
            return Ok(None); // Need more data
        }

        // We have a complete frame
        let frame_data = src.split_to(total_size).freeze();
        Frame::deserialize(frame_data).map(Some)
    }
}

/// Encode a varint (QUIC variable-length integer)
fn encode_varint(buf: &mut BytesMut, value: u64) -> Result<()> {
    match value {
        0..=63 => {
            buf.put_u8(value as u8);
        }
        64..=16383 => {
            buf.put_u16(0x4000 | (value as u16));
        }
        16384..=1073741823 => {
            buf.put_u32(0x80000000 | (value as u32));
        }
        1073741824..=4611686018427387903 => {
            buf.put_u64(0xC000000000000000 | value);
        }
        _ => {
            return Err(HtxError::Protocol("Varint too large".to_string()));
        }
    }
    Ok(())
}

/// Decode a varint (QUIC variable-length integer)
fn decode_varint(buf: &mut Bytes) -> Result<u64> {
    if buf.is_empty() {
        return Err(HtxError::Protocol("Empty buffer for varint".to_string()));
    }

    let first_byte = buf[0];
    let len = match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if buf.len() < len {
        return Err(HtxError::Protocol("Incomplete varint".to_string()));
    }

    let value = match len {
        1 => {
            let val = buf[0] as u64;
            buf.advance(1);
            val
        }
        2 => {
            let val = (((buf[0] & 0x3F) as u64) << 8) | (buf[1] as u64);
            buf.advance(2);
            val
        }
        4 => {
            let val = (((buf[0] & 0x3F) as u64) << 24)
                | ((buf[1] as u64) << 16)
                | ((buf[2] as u64) << 8)
                | (buf[3] as u64);
            buf.advance(4);
            val
        }
        8 => {
            let val = (((buf[0] & 0x3F) as u64) << 56)
                | ((buf[1] as u64) << 48)
                | ((buf[2] as u64) << 40)
                | ((buf[3] as u64) << 32)
                | ((buf[4] as u64) << 24)
                | ((buf[5] as u64) << 16)
                | ((buf[6] as u64) << 8)
                | (buf[7] as u64);
            buf.advance(8);
            val
        }
        _ => unreachable!(),
    };

    Ok(value)
}

/// Estimate header size for frame parsing
fn estimate_header_size(frame_type: &u8) -> Result<usize> {
    let requires_stream_id = matches!(*frame_type, 0 | 4); // STREAM or WINDOW_UPDATE

    if requires_stream_id {
        // Conservative estimate: 1 byte type + up to 8 bytes varint
        Ok(9)
    } else {
        // Just the type byte
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization() {
        let data = Bytes::from("hello world");
        let frame = Frame::stream(123, data.clone());

        let header = frame.serialize_header().unwrap();
        assert!(!header.is_empty());

        // Test round-trip
        let mut full_frame = BytesMut::new();
        full_frame.put_slice(&header);
        full_frame.put_slice(&data);

        let parsed = Frame::deserialize(full_frame.freeze()).unwrap();
        assert_eq!(parsed.frame_type, FrameType::Stream);
        assert_eq!(parsed.stream_id, Some(123));
        assert_eq!(parsed.payload, data);
    }

    #[test]
    fn test_varint_encoding() {
        let mut buf = BytesMut::new();

        // Test small value
        encode_varint(&mut buf, 42).unwrap();
        let mut bytes = buf.freeze();
        assert_eq!(decode_varint(&mut bytes).unwrap(), 42);

        // Test larger value
        let mut buf = BytesMut::new(); // Create new buffer
        encode_varint(&mut buf, 16384).unwrap();
        let mut bytes = buf.freeze();
        assert_eq!(decode_varint(&mut bytes).unwrap(), 16384);
    }

    #[test]
    fn test_frame_types() {
        assert_eq!(FrameType::try_from(0).unwrap(), FrameType::Stream);
        assert_eq!(FrameType::try_from(1).unwrap(), FrameType::Ping);
        assert_eq!(FrameType::try_from(2).unwrap(), FrameType::Close);
        assert_eq!(FrameType::try_from(3).unwrap(), FrameType::KeyUpdate);
        assert_eq!(FrameType::try_from(4).unwrap(), FrameType::WindowUpdate);
        assert_eq!(FrameType::try_from(5).unwrap(), FrameType::Handshake);

        assert!(FrameType::try_from(255).is_err());
    }
}
