// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::{transport::Transport, Error, Request, Response, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
// -----------------------------------------------------------------------------

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Implements a transport layer using a tokio AsyncReadExt and AsyncWriteExt
/// trait, this can be a TLS stream or a TCP stream or anything that implements
/// these traits.
pub struct TransportStream<Read, Write>
where
    Read: AsyncReadExt + std::marker::Unpin + Send,
    Write: AsyncWriteExt + std::marker::Unpin + Send,
{
    read: Mutex<Option<Read>>,
    write: Mutex<Option<Write>>,
}

impl<Read, Write> TransportStream<Read, Write>
where
    Read: AsyncReadExt + std::marker::Unpin + Send,
    Write: AsyncWriteExt + std::marker::Unpin + Send,
{
    pub fn new(read: Read, write: Write) -> Self {
        Self {
            read: Mutex::new(Some(read)),
            write: Mutex::new(Some(write)),
        }
    }
}

#[async_trait]
impl<Read, Write> Transport for TransportStream<Read, Write>
where
    Read: AsyncReadExt + std::marker::Unpin + Send,
    Write: AsyncWriteExt + std::marker::Unpin + Send,
{
    async fn send(&self, request: Request) -> Result<()> {
        if let Some(write) = self.write.lock().await.as_mut() {
            // Serialize the request to a JSON string.
            let payload = serde_json::to_vec(&request)?;

            if payload.len() > MAX_REQUEST_BYTES {
                return Err(Error::RequestTooLarge(payload.len()));
            }

            // Convert the payload length to a big-endian byte array.
            let payload_length: [u8; 4] = (payload.len() as u32).to_be_bytes();

            // Send the payload length to the server.
            write.write_all(&payload_length).await?;

            // Send the payload to the server.
            log::info!("Sending: {:?}", request);
            write.write_all(&payload).await?;

            Ok(())
        } else {
            Err(Error::InvalidAgentConnection(
                "Disconnected stream".to_string(),
            ))
        }
    }

    async fn recv(&self) -> Result<Response> {
        if let Some(read) = self.read.lock().await.as_mut() {
            // Read the payload length from the server.
            let response_length: usize = read.read_u32().await?.try_into()?;

            if response_length > MAX_RESPONSE_BYTES {
                return Err(Error::ResponseTooLarge(response_length));
            }

            // Allocate a buffer of that length.
            let mut buf = vec![0u8; response_length];

            // Read the payload
            read.read_exact(&mut buf).await?;

            let response: Response = serde_json::from_slice(&buf)?;

            log::info!("Receiving: {:?}", response);

            // Deserialize the response from the JSON string.
            Ok(response)
        } else {
            Err(Error::InvalidAgentConnection(
                "Disconnected stream".to_string(),
            ))
        }
    }

    async fn close(&self) -> Result<()> {
        log::info!("TransportStream::close");

        // Only call shutdown if the stream has not already been closed down
        if let Some(mut write) = self.write.lock().await.take() {
            log::info!("TransportStream::close:send shutdown");

            // First explicitly signal the stream shutdown by sending
            // null character.
            write.shutdown().await?;
        }

        // Drop the read stream
        log::info!("TransportStream::close:drop read stream");
        self.read.lock().await.take();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_oversized_response_before_allocating_it() {
        let (mut producer, consumer) = tokio::io::duplex(16);
        let (unused_read, unused_write) = tokio::io::duplex(16);
        let transport = TransportStream::new(consumer, unused_write);
        producer
            .write_all(&((MAX_RESPONSE_BYTES as u32) + 1).to_be_bytes())
            .await
            .expect("write response length");

        assert!(matches!(
            transport.recv().await,
            Err(Error::ResponseTooLarge(length)) if length == MAX_RESPONSE_BYTES + 1
        ));
        drop(unused_read);
    }
}
