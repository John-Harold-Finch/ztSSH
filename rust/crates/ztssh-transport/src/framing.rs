//! Length-prefixed binary message framing over async streams.
//!
//! Wire format: [length: u32 BE] [payload: N bytes]
//! The length field does NOT include itself (4 bytes).

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::TransportError;

/// Maximum allowed message size (64 KB).
const MAX_MESSAGE_SIZE: u32 = 65_536;

/// Write a length-prefixed message to the stream.
pub async fn write_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), TransportError> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed message from the stream.
pub async fn read_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransportError::ConnectionClosed);
        }
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(TransportError::MessageTooLarge(len));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip() {
        let data = b"hello ztssh transport";
        let mut buf = Vec::new();
        write_message(&mut buf, data).await.unwrap();

        let mut cursor = &buf[..];
        let restored = read_message(&mut cursor).await.unwrap();
        assert_eq!(restored, data);
    }

    #[tokio::test]
    async fn empty_message() {
        let mut buf = Vec::new();
        write_message(&mut buf, &[]).await.unwrap();

        let mut cursor = &buf[..];
        let restored = read_message(&mut cursor).await.unwrap();
        assert!(restored.is_empty());
    }

    #[tokio::test]
    async fn connection_closed() {
        let empty: &[u8] = &[];
        let mut cursor = empty;
        let result = read_message(&mut cursor).await;
        assert!(matches!(result, Err(TransportError::ConnectionClosed)));
    }
}
