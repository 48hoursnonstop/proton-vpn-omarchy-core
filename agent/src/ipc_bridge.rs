use proton_omarchy_protocol::MAX_FRAME_BYTES;
use std::{io, path::Path};
use tokio::{
    io::{self as tokio_io, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{unix::OwnedReadHalf, unix::OwnedWriteHalf, UnixStream},
};

const READ_CHUNK_BYTES: usize = 8 * 1024;

/// Runs a bounded stdio bridge for QML. Quickshell's SplitParser has no input
/// ceiling, so it only ever sees frames after this process has validated their
/// size. An oversized or unterminated frame closes both sides immediately.
pub async fn run(socket_path: &Path) -> io::Result<()> {
    let stream = UnixStream::connect(socket_path).await?;
    let (socket_reader, socket_writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
    let stdin = tokio_io::stdin();
    let stdout = tokio_io::stdout();

    tokio::select! {
        result = forward_frames(stdin, socket_writer) => result,
        result = forward_frames(socket_reader, stdout) => result,
    }
}

async fn forward_frames<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    let mut frame = Vec::with_capacity(READ_CHUNK_BYTES);
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            if !frame.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "IPC stream ended with an incomplete frame",
                ));
            }
            writer.shutdown().await?;
            return Ok(());
        }
        for byte in &chunk[..count] {
            if *byte == b'\n' {
                writer.write_all(&frame).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
                frame.clear();
            } else {
                if frame.len() == MAX_FRAME_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPC frame exceeds 64 KiB",
                    ));
                }
                frame.push(*byte);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forwards_complete_bounded_frames() {
        let (mut input, reader) = tokio_io::duplex(128);
        let (writer, mut output) = tokio_io::duplex(128);
        let task = tokio::spawn(forward_frames(reader, writer));
        input.write_all(b"one\ntwo\n").await.unwrap();
        input.shutdown().await.unwrap();
        let mut received = Vec::new();
        output.read_to_end(&mut received).await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(received, b"one\ntwo\n");
    }

    #[tokio::test]
    async fn rejects_a_line_before_split_parser_can_accumulate_it() {
        let capacity = MAX_FRAME_BYTES + 1024;
        let (mut input, reader) = tokio_io::duplex(capacity);
        let (writer, mut output) = tokio_io::duplex(capacity);
        let task = tokio::spawn(forward_frames(reader, writer));
        input
            .write_all(&vec![b'x'; MAX_FRAME_BYTES + 1])
            .await
            .unwrap();
        input.shutdown().await.unwrap();
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let mut received = Vec::new();
        output.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }
}
