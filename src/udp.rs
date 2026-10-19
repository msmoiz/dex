use anyhow::Context;

use crate::{
    addr::{resolve_nameserver, unspecified_for},
    Bytes, Message,
};

/// Message transport over UDP.
pub struct UdpTransport {
    nameserver: String,
    max_response_size: u16,
}

impl UdpTransport {
    /// Creates a new UdpTransport object.
    pub fn new(nameserver: String, max_size: u16) -> Self {
        Self {
            nameserver,
            max_response_size: max_size,
        }
    }

    /// Sends a DNS request.
    pub fn send(&self, request: Message) -> anyhow::Result<Message> {
        let err = || format!("failed to send packet to nameserver: {}", self.nameserver);
        let addr = resolve_nameserver(&self.nameserver).with_context(err)?;
        let socket = std::net::UdpSocket::bind(unspecified_for(&addr)).unwrap();

        let mut request_bytes = Bytes::new();
        request.to_bytes(&mut request_bytes);

        socket
            .send_to(request_bytes.used(), addr)
            .with_context(err)?;

        let mut response_buf = vec![0; self.max_response_size as usize];
        let (_, _) = socket.recv_from(&mut response_buf).unwrap();
        let mut response_bytes = Bytes::from_buf(&response_buf);
        let response = Message::from_bytes(&mut response_bytes);

        Ok(response)
    }
}
