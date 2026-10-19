use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::Context;

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
    pub fn send(&self, request: Message) -> anyhow::Result<Message> {
        let err = || format!("failed to connect to nameserver: {}", self.nameserver);
        let mut socket = if self.nameserver.contains(":") {
            TcpStream::connect(&self.nameserver).with_context(err)?
        } else {
            TcpStream::connect((self.nameserver.as_str(), 53)).with_context(err)?
        };

        let mut request_bytes = Bytes::new();
        request.to_bytes(&mut request_bytes);
        let request_len = &(request_bytes.used().len() as u16).to_be_bytes();
        socket.write(request_len)?;
        socket.write(request_bytes.used())?;

        let mut response_len_buf = [0; 2];
        socket.read_exact(&mut response_len_buf)?;
        let response_len = u16::from_be_bytes(response_len_buf);
        let mut response_buf = vec![0; response_len as usize];
        socket.read_exact(&mut response_buf)?;
        let mut response_bytes = Bytes::from_buf(&response_buf);
        let response = Message::from_bytes(&mut response_bytes);

        Ok(response)
    }
}
