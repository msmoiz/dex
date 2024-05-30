use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use serde::Deserialize;

fn main() {
    serve();
}

fn serve() {
    println!("listening on port 5380");
    let socket = std::net::UdpSocket::bind("0.0.0.0:5380").unwrap();
    loop {
        let mut buf = [0; 512];
        let (_, addr) = socket.recv_from(&mut buf).unwrap();
        println!("received connection from addr: {addr}");
        let mut bytes = Bytes::from_buf(&buf);
        let header = Header::from_bytes(&mut bytes);
        println!("{header:?}");
        for _ in 0..header.question_count {
            let question = Question::from_bytes(&mut bytes);
            println!("{question:?}");
        }
    }
}

/// A DNS resource record.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
enum Record {
    /// IPv4 address record.
    A {
        name: String,
        class: RecordClass,
        ttl: u32,
        addr: Ipv4Addr,
    },
    /// IPv6 address record.
    Aaaa {
        name: String,
        class: RecordClass,
        ttl: u32,
        addr: Ipv6Addr,
    },
    /// Canonical name record.
    Cname {
        name: String,
        class: RecordClass,
        ttl: u32,
        host: String,
    },
    /// Mail exchange record.
    Mx {
        name: String,
        class: RecordClass,
        ttl: u32,
        priority: u16,
        host: String,
    },
    /// Name server record.
    Ns {
        name: String,
        class: RecordClass,
        ttl: u32,
        host: String,
    },
    /// Text record.
    Txt {
        name: String,
        class: RecordClass,
        ttl: u32,
        content: String,
    },
}

impl Record {
    /// Returns the name of the record.
    fn name(&self) -> &str {
        match self {
            Record::A { name, .. } => name,
            Record::Aaaa { name, .. } => name,
            Record::Cname { name, .. } => name,
            Record::Mx { name, .. } => name,
            Record::Ns { name, .. } => name,
            Record::Txt { name, .. } => name,
        }
    }

    /// Returns the class of the record.
    fn class(&self) -> RecordClass {
        match self {
            Record::A { class, .. } => class,
            Record::Aaaa { class, .. } => class,
            Record::Cname { class, .. } => class,
            Record::Mx { class, .. } => class,
            Record::Ns { class, .. } => class,
            Record::Txt { class, .. } => class,
        }
        .clone()
    }

    /// Returns the ttl of the record.
    fn ttl(&self) -> u32 {
        *match self {
            Record::A { ttl, .. } => ttl,
            Record::Aaaa { ttl, .. } => ttl,
            Record::Cname { ttl, .. } => ttl,
            Record::Mx { ttl, .. } => ttl,
            Record::Ns { ttl, .. } => ttl,
            Record::Txt { ttl, .. } => ttl,
        }
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {} ", self.name(), self.class(), self.ttl())?;
        match self {
            Record::A { addr, .. } => write!(f, "A {addr}"),
            Record::Aaaa { addr, .. } => write!(f, "AAAA {addr}"),
            Record::Cname { host, .. } => write!(f, "CNAME {host}"),
            Record::Mx { priority, host, .. } => write!(f, "MX {priority} {host}"),
            Record::Ns { host, .. } => write!(f, "NS {host}"),
            Record::Txt { content, .. } => write!(f, "TXT {content}"),
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum RecordClass {
    /// Internet.
    #[default]
    In,
    /// Chaos.
    Ch,
    /// Hesiod.
    Hs,
}

impl Display for RecordClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            RecordClass::In => "IN",
            RecordClass::Ch => "CH",
            RecordClass::Hs => "HS",
        };

        write!(f, "{code}")
    }
}

/// A subset of the DNS namespace.
///
/// This usually represents a single domain.
#[derive(Deserialize)]
struct Zone {
    /// Records in the zone.
    records: Vec<Record>,
}

impl Zone {
    /// Parse a Zone from an input text in TOML format.
    ///
    /// The input should contain a `records` list with one record per item.
    /// Records must have the following fields:
    ///
    /// * `name`: The name of the record.
    /// * `class`: The class of the record (usually "IN").
    /// * `ttl`: The time-to-live of the record.
    /// * `type`: The type of the record.
    ///
    /// In addition, records must contain record data corresponding to the
    /// record type. For more information on expected fields for each type,
    /// refer to the [`Record`] documentation.
    ///
    /// # Example
    ///
    /// The following example defines a zone with one address record.
    ///  
    /// ```toml
    /// [[records]]
    /// name = "example.com."
    /// class = "IN"
    /// ttl = 60
    /// type = "A"
    /// addr = "0.0.0.0"
    /// ```
    fn from_toml(input: &str) -> Result<Self> {
        let zone = toml::from_str(input)?;
        Ok(zone)
    }
}

struct Message {
    header: Header,
    questions: Vec<Question>,
}

/// Message header.
#[derive(Debug)]
struct Header {
    id: u16,
    is_response: bool,
    op_code: u8,
    is_authority: bool,
    is_truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    resp_code: u8,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl Header {
    /// Creates a Header from a byte stream.
    fn from_bytes(bytes: &mut Bytes) -> Self {
        let id = {
            let bytez = bytes.read_exact(2).unwrap();
            u16::from_be_bytes(bytez.try_into().unwrap())
        };

        let (is_response, op_code, is_authority, is_truncated, recursion_desired) = {
            let byte = bytes.read().unwrap();
            let is_response = ((byte >> 7) & 1) == 1;
            let op_code = (byte & (0b1111 << 3)) >> 3;
            let is_authority = ((byte >> 2) & 1) == 1;
            let is_truncated = ((byte >> 1) & 1) == 1;
            let recursion_desired = (byte & 1) == 1;
            (
                is_response,
                op_code,
                is_authority,
                is_truncated,
                recursion_desired,
            )
        };

        let (recursion_available, resp_code) = {
            let byte = bytes.read().unwrap();
            let recursion_available = ((byte >> 7) & 1) == 1;
            let resp_code = byte & 0b1111;
            (recursion_available, resp_code)
        };

        let question_count = {
            let bytez = bytes.read_exact(2).unwrap();
            u16::from_be_bytes(bytez.try_into().unwrap())
        };

        let answer_count = {
            let bytez = bytes.read_exact(2).unwrap();
            u16::from_be_bytes(bytez.try_into().unwrap())
        };

        let authority_count = {
            let bytez = bytes.read_exact(2).unwrap();
            u16::from_be_bytes(bytez.try_into().unwrap())
        };

        let additional_count = {
            let bytez = bytes.read_exact(2).unwrap();
            u16::from_be_bytes(bytez.try_into().unwrap())
        };

        Self {
            id,
            is_response,
            op_code,
            is_authority,
            is_truncated,
            recursion_desired,
            recursion_available,
            resp_code,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        }
    }
}

/// A DNS question.
#[derive(Debug)]
struct Question {
    name: String,
    q_type: u16,
    q_class: u16,
}

impl Question {
    /// Creates a Question from a byte stream.
    fn from_bytes(bytes: &mut Bytes) -> Self {
        let mut labels = vec![];

        loop {
            let len = bytes.read().unwrap();
            if len == 0 {
                break;
            }
            let bytez = bytes.read_exact(len as usize).unwrap();
            let label = String::from_utf8(bytez).unwrap();
            labels.push(label);
        }

        let name = labels.join(".");

        let q_type = {
            let bytez = bytes.read_exact(2).unwrap();
            u16::from_be_bytes(bytez.try_into().unwrap())
        };

        let q_class = {
            let bytez = bytes.read_exact(2).unwrap();
            u16::from_be_bytes(bytez.try_into().unwrap())
        };

        Self {
            name,
            q_type,
            q_class,
        }
    }
}

/// An iterator over a byte buffer.
struct Bytes<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Bytes<'a> {
    /// Creates a new Bytes iterator.
    fn from_buf(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns a slice that represents the unread bytes.
    fn remainder(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Reads the next byte from the buffer.
    ///
    /// Returns None if the end of the buffer has been reached.
    fn read(&mut self) -> Option<u8> {
        if self.remainder().len() == 0 {
            return None;
        }
        let byte = self.remainder()[0];
        self.pos += 1;
        Some(byte)
    }

    /// Reads the next n bytes from the buffer.
    ///
    /// Returns None if the end of the buffer has been reached.
    fn read_exact(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.remainder().len() < n {
            return None;
        }
        let bytes: Vec<_> = self.remainder()[..n].iter().map(|b| b.to_owned()).collect();
        self.pos += n;
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::Zone;

    #[test]
    fn parse_toml() {
        let input = r#"
            [[records]]
            name = "example.com."
            class = "IN"
            ttl = 60
            type = "A"
            addr = "0.0.0.0"
        "#;

        let zone: Zone = Zone::from_toml(input).unwrap();
        assert_eq!(zone.records[0].name(), "example.com.")
    }
}
