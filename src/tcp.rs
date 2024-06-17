use std::{
    io::{Read, Write},
    net::TcpStream,
};

use crate::{Bytes, Message};

/// Message transport over TCP.
pub struct TcpTransport {
    nameserver: String,
}

impl TcpTransport {
    /// Creates a new TcpTransport object.
    pub fn new(nameserver: String) -> Self {
        Self { nameserver }
    }

    /// Sends a DNS request.
    pub fn send(&self, request: Message) -> Message {
        let mut socket = if self.nameserver.contains(":") {
            TcpStream::connect(&self.nameserver).unwrap()
        } else {
            TcpStream::connect((self.nameserver.as_str(), 53)).unwrap()
        };

        let mut request_bytes = Bytes::new();
        request.to_bytes(&mut request_bytes);
        let request_len = &(request_bytes.used().len() as u16).to_be_bytes();
        socket.write(request_len).unwrap();
        socket.write(request_bytes.used()).unwrap();

        let mut response_len_buf = [0; 2];
        socket.read_exact(&mut response_len_buf).unwrap();
        let response_len = u16::from_be_bytes(response_len_buf);
        let mut response_buf = vec![0; response_len as usize];
        socket.read_exact(&mut response_buf).unwrap();
        response_buf.resize(512, 0);
        let mut response_bytes = Bytes::from_buf(response_buf.try_into().unwrap());
        let response = Message::from_bytes(&mut response_bytes);

        response
    }
}
