//! The server side of a bridge's WebSocket (RFC 6455, no extensions), holding no buffer while a socket is idle.
//!
//! Most bridges are idle, with a ping every 15 s. tungstenite reserved a 128 KiB read buffer per socket and kept
//! its read and write buffers as large as the largest frame the socket ever carried, so a bridge that had carried
//! visitors held ~100 KB for the rest of its life. Here the read buffer is released whenever it is empty (a
//! frame's payload keeps only its own bytes), and frames are written straight from their payload.

use std::io::{self, IoSlice};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// What a read asks for at least while no frame is in progress: control messages fit in one read.
const READ_CHUNK: usize = 4 * 1024;

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xa;

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    /// The peer's close code, 1005 when its close frame had none.
    Close(u16),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("WebSocket protocol error: {0}")]
    Protocol(&'static str),
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: BytesMut,
}

/// Reads messages from a client: frames must be masked, and no frame or message may exceed `max_message`.
pub struct Reader<R> {
    io: R,
    buffer: BytesMut,
    /// Bytes the frame at the front of `buffer` needs in all, once its header is known.
    wanted: usize,
    max_message: usize,
    /// A fragmented message being assembled: whether it is text, and its data so far.
    partial: Option<(bool, BytesMut)>,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(io: R, max_message: usize) -> Self {
        Self {
            io,
            buffer: BytesMut::new(),
            wanted: 0,
            max_message,
            partial: None,
        }
    }

    /// Bytes held for frames not complete yet (0 between messages, when nothing more has arrived).
    pub fn buffered(&self) -> usize {
        self.buffer.capacity()
    }

    /// The next message, or `None` once the connection ends without a close frame.
    pub async fn next(&mut self) -> Result<Option<Message>, Error> {
        loop {
            if let Some(message) = self.parse()? {
                return Ok(Some(message));
            }
            let missing = self.wanted.saturating_sub(self.buffer.len());
            // One allocation for the rest of a large frame, so its payload is never copied.
            self.buffer.reserve(missing.max(READ_CHUNK));
            if self.io.read_buf(&mut self.buffer).await? == 0 {
                return Ok(None);
            }
        }
    }

    /// The next complete message in the buffer, consuming the frames it took.
    fn parse(&mut self) -> Result<Option<Message>, Error> {
        loop {
            let Some(frame) = self.frame()? else {
                return Ok(None);
            };
            if frame.opcode >= CLOSE {
                if !frame.fin || frame.payload.len() > 125 {
                    return Err(Error::Protocol("invalid control frame"));
                }
                let payload = frame.payload.freeze();
                return Ok(Some(match frame.opcode {
                    CLOSE => match payload.len() {
                        0 => Message::Close(1005),
                        1 => return Err(Error::Protocol("invalid close frame")),
                        _ => {
                            if std::str::from_utf8(&payload[2..]).is_err() {
                                return Err(Error::Protocol("invalid close reason"));
                            }
                            Message::Close(u16::from_be_bytes([payload[0], payload[1]]))
                        }
                    },
                    PING => Message::Ping(payload),
                    PONG => Message::Pong(payload),
                    _ => return Err(Error::Protocol("unknown opcode")),
                }));
            }
            let (text, data) = match (frame.opcode, self.partial.take()) {
                (TEXT | BINARY, None) => (frame.opcode == TEXT, frame.payload),
                (CONTINUATION, Some((text, mut data))) => {
                    if data.len() + frame.payload.len() > self.max_message {
                        return Err(Error::Protocol("message too large"));
                    }
                    data.extend_from_slice(&frame.payload);
                    (text, data)
                }
                (TEXT | BINARY, Some(_)) => return Err(Error::Protocol("expected a continuation")),
                (CONTINUATION, None) => return Err(Error::Protocol("unexpected continuation")),
                _ => return Err(Error::Protocol("unknown opcode")),
            };
            if !frame.fin {
                self.partial = Some((text, data));
                continue;
            }
            return Ok(Some(if text {
                Message::Text(
                    String::from_utf8(Vec::from(data))
                        .map_err(|_| Error::Protocol("text is not UTF-8"))?,
                )
            } else {
                Message::Binary(data.freeze())
            }));
        }
    }

    /// Splits the frame at the front of the buffer off, unmasked, once it is complete.
    fn frame(&mut self) -> Result<Option<Frame>, Error> {
        let buffer = &self.buffer[..];
        self.wanted = 2;
        if buffer.len() < 2 {
            return Ok(None);
        }
        if buffer[0] & 0x70 != 0 {
            return Err(Error::Protocol("reserved bits set"));
        }
        if buffer[1] & 0x80 == 0 {
            return Err(Error::Protocol("unmasked client frame"));
        }
        let (length, offset) = match buffer[1] & 0x7f {
            126 if buffer.len() < 4 => {
                self.wanted = 4;
                return Ok(None);
            }
            126 => (u64::from(u16::from_be_bytes([buffer[2], buffer[3]])), 4),
            127 if buffer.len() < 10 => {
                self.wanted = 10;
                return Ok(None);
            }
            127 => (
                u64::from_be_bytes(buffer[2..10].try_into().expect("8 bytes")),
                10,
            ),
            length => (u64::from(length), 2),
        };
        if length > self.max_message as u64 {
            return Err(Error::Protocol("frame too large"));
        }
        let length = length as usize;
        self.wanted = offset + 4 + length;
        if buffer.len() < self.wanted {
            return Ok(None);
        }
        let mask: [u8; 4] = buffer[offset..offset + 4].try_into().expect("4 bytes");
        let fin = buffer[0] & 0x80 != 0;
        let opcode = buffer[0] & 0x0f;
        self.buffer.advance(offset + 4);
        let mut payload = self.buffer.split_to(length);
        unmask(&mut payload, mask);
        if self.buffer.is_empty() {
            // The allocation now belongs to the payload alone, and goes with it.
            self.buffer = BytesMut::new();
        }
        self.wanted = 0;
        Ok(Some(Frame {
            fin,
            opcode,
            payload,
        }))
    }
}

fn unmask(data: &mut [u8], mask: [u8; 4]) {
    let wide = u64::from_ne_bytes([
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ]);
    let (chunks, rest) = data.as_chunks_mut::<8>();
    for chunk in chunks {
        *chunk = (u64::from_ne_bytes(*chunk) ^ wide).to_ne_bytes();
    }
    for (index, byte) in rest.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

/// Writes unmasked frames to a client, each as one final frame.
pub struct Writer<W> {
    io: W,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(io: W) -> Self {
        Self { io }
    }

    pub async fn text(&mut self, text: &str) -> io::Result<()> {
        self.frame(TEXT, &[], text.as_bytes()).await
    }

    pub async fn binary(&mut self, data: &[u8]) -> io::Result<()> {
        self.frame(BINARY, &[], data).await
    }

    pub async fn pong(&mut self, data: &[u8]) -> io::Result<()> {
        self.frame(PONG, &[], data).await
    }

    /// A close frame with `code` and `reason` (cut to fit a control frame), or none for `None`.
    pub async fn close(&mut self, close: Option<(u16, &str)>) -> io::Result<()> {
        match close {
            Some((code, reason)) => {
                let mut end = reason.len().min(123);
                while !reason.is_char_boundary(end) {
                    end -= 1;
                }
                self.frame(CLOSE, &code.to_be_bytes(), &reason.as_bytes()[..end])
                    .await
            }
            None => self.frame(CLOSE, &[], &[]).await,
        }
    }

    /// Ends the stream (TLS close_notify and a FIN).
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.io.shutdown().await
    }

    async fn frame(&mut self, opcode: u8, prefix: &[u8], payload: &[u8]) -> io::Result<()> {
        let length = prefix.len() + payload.len();
        let mut header = [0u8; 10];
        header[0] = 0x80 | opcode;
        let header_length = if length < 126 {
            header[1] = length as u8;
            2
        } else if let Ok(length) = u16::try_from(length) {
            header[1] = 126;
            header[2..4].copy_from_slice(&length.to_be_bytes());
            4
        } else {
            header[1] = 127;
            header[2..10].copy_from_slice(&(length as u64).to_be_bytes());
            10
        };
        let mut slices = [
            IoSlice::new(&header[..header_length]),
            IoSlice::new(prefix),
            IoSlice::new(payload),
        ];
        let mut slices = &mut slices[..];
        IoSlice::advance_slices(&mut slices, 0);
        while !slices.is_empty() {
            let written = self.io.write_vectored(slices).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            IoSlice::advance_slices(&mut slices, written);
        }
        self.io.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// A frame as a client sends it, masked.
    fn client_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        let mut frame = vec![(u8::from(fin) << 7) | opcode];
        match payload.len() {
            length @ 0..126 => frame.push(0x80 | length as u8),
            length @ 126..65536 => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(length as u16).to_be_bytes());
            }
            length => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(length as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        frame
    }

    async fn read_all(bytes: Vec<u8>, max: usize) -> Vec<Result<Message, String>> {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        client.write_all(&bytes).await.unwrap();
        drop(client);
        let mut reader = Reader::new(server, max);
        let mut messages = Vec::new();
        loop {
            match reader.next().await {
                Ok(Some(message)) => messages.push(Ok(message)),
                Ok(None) => return messages,
                Err(error) => {
                    messages.push(Err(error.to_string()));
                    return messages;
                }
            }
        }
    }

    #[tokio::test]
    async fn reads_messages_of_every_size_and_kind() {
        let large: Vec<u8> = (0..40_000u32).map(|index| index as u8).collect();
        let huge: Vec<u8> = (0..70_000u32).map(|index| (index * 7) as u8).collect();
        let mut bytes = client_frame(true, TEXT, br#"{"type":"ping"}"#);
        bytes.extend(client_frame(true, BINARY, &large));
        bytes.extend(client_frame(true, BINARY, &huge));
        bytes.extend(client_frame(true, PING, b"hi"));
        bytes.extend(client_frame(true, BINARY, &[]));
        bytes.extend(client_frame(true, CLOSE, &[0x03, 0xe8, b'o', b'k']));
        assert_eq!(
            read_all(bytes, 1 << 20).await,
            vec![
                Ok(Message::Text(r#"{"type":"ping"}"#.into())),
                Ok(Message::Binary(large.into())),
                Ok(Message::Binary(huge.into())),
                Ok(Message::Ping(Bytes::from_static(b"hi"))),
                Ok(Message::Binary(Bytes::new())),
                Ok(Message::Close(1000)),
            ]
        );
    }

    #[tokio::test]
    async fn assembles_fragments_around_control_frames() {
        let mut bytes = client_frame(false, TEXT, b"{\"type\":");
        bytes.extend(client_frame(true, PING, b""));
        bytes.extend(client_frame(false, CONTINUATION, b"\"pi"));
        bytes.extend(client_frame(true, CONTINUATION, b"ng\"}"));
        bytes.extend(client_frame(true, CLOSE, &[]));
        assert_eq!(
            read_all(bytes, 1024).await,
            vec![
                Ok(Message::Ping(Bytes::new())),
                Ok(Message::Text(r#"{"type":"ping"}"#.into())),
                Ok(Message::Close(1005)),
            ]
        );
    }

    #[tokio::test]
    async fn rejects_protocol_violations() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0x82, 0x01, 0xff], "unmasked client frame"),
            (client_frame(true, 0x3, b""), "unknown opcode"),
            (client_frame(true, 0x40 | BINARY, b""), "reserved bits set"),
            (
                client_frame(true, CONTINUATION, b"x"),
                "unexpected continuation",
            ),
            (client_frame(false, PING, b""), "invalid control frame"),
            (client_frame(true, PING, &[0; 126]), "invalid control frame"),
            (client_frame(true, CLOSE, &[3]), "invalid close frame"),
            (client_frame(true, TEXT, &[0xff, 0xfe]), "text is not UTF-8"),
            (client_frame(true, BINARY, &[0; 1025]), "frame too large"),
            (
                [
                    client_frame(false, BINARY, &[0; 1000]),
                    client_frame(true, CONTINUATION, &[0; 100]),
                ]
                .concat(),
                "message too large",
            ),
            (
                [
                    client_frame(false, TEXT, b"a"),
                    client_frame(true, TEXT, b"b"),
                ]
                .concat(),
                "expected a continuation",
            ),
        ];
        for (bytes, expected) in cases {
            let messages = read_all(bytes, 1024).await;
            assert_eq!(
                messages.last(),
                Some(&Err(format!("WebSocket protocol error: {expected}"))),
                "{expected}"
            );
        }
    }

    #[tokio::test]
    async fn holds_no_buffer_between_messages() {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let mut reader = Reader::new(server, 1 << 20);
        client
            .write_all(&client_frame(true, BINARY, &[7; 32 * 1024]))
            .await
            .unwrap();
        let Some(Message::Binary(data)) = reader.next().await.unwrap() else {
            panic!("expected a binary message");
        };
        assert_eq!(data.len(), 32 * 1024);
        assert_eq!(reader.buffered(), 0);
        // Byte by byte: partial headers and payloads wait for the rest.
        let writing = tokio::spawn(async move {
            for byte in client_frame(true, TEXT, b"{}") {
                client.write_all(&[byte]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            client
        });
        assert_eq!(
            reader.next().await.unwrap(),
            Some(Message::Text("{}".into()))
        );
        assert_eq!(reader.buffered(), 0);
        drop(writing.await.unwrap());
        assert_eq!(reader.next().await.unwrap(), None);
    }

    #[tokio::test]
    async fn writes_frames_tungstenite_reads() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as Tungstenite;
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (client, server) = tokio::io::duplex(1 << 20);
        let mut writer = Writer::new(server);
        let large = vec![9u8; 70_000];
        writer.text("{\"type\":\"pong\"}").await.unwrap();
        writer.binary(&[1; 200]).await.unwrap();
        writer.binary(&large).await.unwrap();
        writer.pong(b"p").await.unwrap();
        writer.close(Some((1012, &"é".repeat(100)))).await.unwrap();
        let mut client =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            Tungstenite::text("{\"type\":\"pong\"}")
        );
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            Tungstenite::binary(vec![1; 200])
        );
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            Tungstenite::binary(large)
        );
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            Tungstenite::Pong(Bytes::from_static(b"p"))
        );
        let Tungstenite::Close(Some(frame)) = client.next().await.unwrap().unwrap() else {
            panic!("expected a close frame");
        };
        assert_eq!(u16::from(frame.code), 1012);
        assert_eq!(frame.reason.len(), 122);
    }
}
