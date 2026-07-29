pub const MAGIC: [u8; 4] = *b"STRL";
pub const MAJOR: u16 = 1;
pub const HEADER_BYTES: usize = 12;
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

pub const KIND_EVENT_V1: u16 = 0x0001;

pub async fn read_frame<R>(reader: &mut R) -> anyhow::Result<(FrameHeader, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut encoded_header = [0_u8; HEADER_BYTES];
    reader
        .read_exact(&mut encoded_header)
        .await
        .map_err(|error| anyhow::anyhow!("truncated frame header: {error}"))?;
    let header = FrameHeader::decode(encoded_header)?;
    let mut body = vec![0_u8; header.body_len as usize];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|error| anyhow::anyhow!("truncated frame body: {error}"))?;
    Ok((header, body))
}

pub async fn write_frame<W>(writer: &mut W, kind: u16, body: &[u8]) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let header = FrameHeader::new(kind, body.len())?;
    writer.write_all(&header.encode()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub kind: u16,
    pub body_len: u32,
}

impl FrameHeader {
    pub fn new(kind: u16, body_len: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(body_len <= MAX_BODY_BYTES, "frame body is too large");
        Ok(Self {
            kind,
            body_len: body_len.try_into()?,
        })
    }

    pub fn encode(self) -> [u8; HEADER_BYTES] {
        let mut out = [0_u8; HEADER_BYTES];
        out[..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&MAJOR.to_be_bytes());
        out[6..8].copy_from_slice(&self.kind.to_be_bytes());
        out[8..12].copy_from_slice(&self.body_len.to_be_bytes());
        out
    }

    pub fn decode(bytes: [u8; HEADER_BYTES]) -> anyhow::Result<Self> {
        anyhow::ensure!(bytes[..4] == MAGIC, "invalid Starling frame magic");
        let major = u16::from_be_bytes(bytes[4..6].try_into()?);
        anyhow::ensure!(
            major == MAJOR,
            "unsupported Starling protocol version {major}"
        );
        let kind = u16::from_be_bytes(bytes[6..8].try_into()?);
        Self::new(kind, u32::from_be_bytes(bytes[8..12].try_into()?) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FrameHeader, HEADER_BYTES, KIND_EVENT_V1, MAGIC, MAJOR, MAX_BODY_BYTES, read_frame,
        write_frame,
    };

    #[test]
    fn header_round_trips() {
        let header = FrameHeader::new(KIND_EVENT_V1, 1_024).expect("valid header");
        let encoded = header.encode();

        assert_eq!(&encoded[..4], &MAGIC);
        assert_eq!(u16::from_be_bytes(encoded[4..6].try_into().unwrap()), MAJOR);
        assert_eq!(FrameHeader::decode(encoded).unwrap(), header);
    }

    #[tokio::test]
    async fn framed_io_round_trips_and_rejects_oversized_writes() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let send = tokio::spawn(async move { write_frame(&mut client, 7, b"hello").await });
        let (header, body) = read_frame(&mut server).await.expect("read frame");

        assert_eq!(header.kind, 7);
        assert_eq!(body, b"hello");
        send.await.unwrap().unwrap();

        let (mut client, _) = tokio::io::duplex(1);
        assert!(
            write_frame(&mut client, 1, &vec![0; MAX_BODY_BYTES + 1])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_truncated_header_and_body() {
        let mut short_header: &[u8] = &FrameHeader::new(1, 0).unwrap().encode()[..8];
        assert!(read_frame(&mut short_header).await.is_err());

        let mut bytes = FrameHeader::new(1, 5).unwrap().encode().to_vec();
        bytes.extend_from_slice(b"four");
        let mut short_body = bytes.as_slice();
        assert!(read_frame(&mut short_body).await.is_err());
    }

    #[test]
    fn rejects_invalid_magic_version_and_oversized_bodies() {
        let mut invalid_magic = FrameHeader::new(1, 0).unwrap().encode();
        invalid_magic[0] ^= 0xff;
        assert!(FrameHeader::decode(invalid_magic).is_err());

        let mut invalid_version = FrameHeader::new(1, 0).unwrap().encode();
        invalid_version[4..6].copy_from_slice(&(MAJOR + 1).to_be_bytes());
        assert!(FrameHeader::decode(invalid_version).is_err());
        assert!(FrameHeader::new(1, MAX_BODY_BYTES + 1).is_err());

        let mut oversized = [0_u8; HEADER_BYTES];
        oversized[..4].copy_from_slice(&MAGIC);
        oversized[4..6].copy_from_slice(&MAJOR.to_be_bytes());
        oversized[6..8].copy_from_slice(&1_u16.to_be_bytes());
        oversized[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(FrameHeader::decode(oversized).is_err());
    }
}
