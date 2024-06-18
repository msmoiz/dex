use crate::{Bytes, Message};

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
    pub fn send(&self, request: Message) -> Message {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();

        let mut request_bytes = Bytes::new();
        request.to_bytes(&mut request_bytes);

        if self.nameserver.contains(":") {
            socket
                .send_to(request_bytes.used(), &self.nameserver)
                .unwrap();
        } else {
            socket
                .send_to(request_bytes.used(), (self.nameserver.as_str(), 53))
                .unwrap();
        }

        let mut response_buf = vec![0; self.max_response_size as usize];
        let (_, _) = socket.recv_from(&mut response_buf).unwrap();
        let mut response_bytes = Bytes::from_buf(&response_buf);
        let response = Message::from_bytes(&mut response_bytes);

        response
    }
}
