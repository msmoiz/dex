use std::{
    fmt::Display,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use serde::Deserialize;

fn main() {
    serve();
}

fn serve() {
    let zone_file = "zone.toml";
    println!("reading zone data from {zone_file}");
    let zone_data = fs::read_to_string(zone_file).unwrap();
    let zone = Zone::from_toml(&zone_data).unwrap();

    println!("listening on port 5380");
    let socket = std::net::UdpSocket::bind("0.0.0.0:5380").unwrap();
    loop {
        let mut buf = [0; 512];
        let (_, addr) = socket.recv_from(&mut buf).unwrap();
        println!("received connection from addr: {addr}");

        let mut bytes = Bytes::from_buf(&buf);
        let message = Message::from_bytes(&mut bytes);
        let question = &message.questions[0];
        println!("message: {} {}", question.name, question.q_type);

        let mut response = message;
        response.header.is_response = true;
        match zone
            .records
            .iter()
            .find(|r| r.name() == response.questions[0].name)
        {
            Some(record) => {
                response.header.is_authority = true;
                response.header.resp_code = 0;
                response.header.answer_count = 1;
                response.answer_records.push(record.clone());
            }
            None => {
                response.header.resp_code = 3;
            }
        }

        let buf = response.to_bytes();
        socket.send_to(&buf, addr).unwrap();
    }
}

/// A DNS resource record.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
enum Record {
    /// IPv4 address record.
    A {
        name: String,
        class: Class,
        ttl: u32,
        addr: Ipv4Addr,
    },
    /// IPv6 address record.
    Aaaa {
        name: String,
        class: Class,
        ttl: u32,
        addr: Ipv6Addr,
    },
    /// Canonical name record.
    Cname {
        name: String,
        class: Class,
        ttl: u32,
        host: String,
    },
    /// Mail exchange record.
    Mx {
        name: String,
        class: Class,
        ttl: u32,
        priority: u16,
        host: String,
    },
    /// Name server record.
    Ns {
        name: String,
        class: Class,
        ttl: u32,
        host: String,
    },
    /// Text record.
    Txt {
        name: String,
        class: Class,
        ttl: u32,
        content: String,
    },
}

impl Record {
    /// Creates a Record from a byte stream.
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
        labels.push("".to_string());

        let name = labels.join(".");

        let r_type = bytes.read_u16().unwrap();
        let r_class = bytes.read_u16().unwrap();
        let ttl = bytes.read_u32().unwrap();
        let _rd_len = bytes.read_u16().unwrap();

        // @todo: support all types
        match r_type {
            1 => {
                let addr = bytes.read_u32().unwrap().into();

                Self::A {
                    name,
                    class: r_class.into(),
                    ttl,
                    addr,
                }
            }
            _ => todo!(),
        }
    }

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
    fn class(&self) -> Class {
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

    /// Converts a Record to a byte stream.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        for label in self.name().split(".") {
            if label == "" {
                bytes.push(0);
                break;
            }
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }

        let r_code = match self {
            Record::A { .. } => 1 as u16,
            _ => unimplemented!(),
        };
        bytes.extend(r_code.to_be_bytes());

        bytes.extend(u16::from(self.class()).to_be_bytes());
        bytes.extend(self.ttl().to_be_bytes());

        match self {
            Record::A { addr, .. } => {
                bytes.extend((4 as u16).to_be_bytes());
                bytes.extend(addr.octets());
            }
            _ => unimplemented!(),
        }

        bytes
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

/// DNS record class.
#[derive(Default, Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum Class {
    /// Internet.
    #[default]
    In,
    /// CS Net.
    Cs,
    /// Chaos.
    Ch,
    /// Hesiod.
    Hs,
}

impl Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Class::In => "IN",
            Class::Cs => "CS",
            Class::Ch => "CH",
            Class::Hs => "HS",
        };

        write!(f, "{code}")
    }
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        match value {
            1 => Class::In,
            2 => Class::Cs,
            3 => Class::Ch,
            4 => Class::Hs,
            _ => panic!("unsupported class: {value}"),
        }
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> Self {
        match value {
            Class::In => 1,
            Class::Cs => 2,
            Class::Ch => 3,
            Class::Hs => 4,
        }
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

/// A DNS message.
#[derive(Debug)]
struct Message {
    header: Header,
    questions: Vec<Question>,
    answer_records: Vec<Record>,
    authority_records: Vec<Record>,
    additional_records: Vec<Record>,
}

impl Message {
    /// Creates a Message from a byte stream.
    fn from_bytes(bytes: &mut Bytes) -> Self {
        let header = Header::from_bytes(bytes);

        let questions: Vec<_> = (0..header.question_count)
            .map(|_| Question::from_bytes(bytes))
            .collect();

        let answer_records: Vec<_> = (0..header.answer_count)
            .map(|_| Record::from_bytes(bytes))
            .collect();

        let authority_records: Vec<_> = (0..header.authority_count)
            .map(|_| Record::from_bytes(bytes))
            .collect();

        let additional_records: Vec<_> = (0..header.additional_count)
            .map(|_| Record::from_bytes(bytes))
            .collect();

        Self {
            header,
            questions,
            answer_records,
            authority_records,
            additional_records,
        }
    }

    /// Converts a Message to a byte stream.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.header.to_bytes());

        for question in &self.questions {
            bytes.extend(question.to_bytes());
        }

        for record in &self.answer_records {
            bytes.extend(record.to_bytes());
        }

        for record in &self.authority_records {
            bytes.extend(record.to_bytes());
        }

        for record in &self.additional_records {
            bytes.extend(record.to_bytes());
        }

        bytes
    }
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
        let id = bytes.read_u16().unwrap();

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

        let question_count = bytes.read_u16().unwrap();
        let answer_count = bytes.read_u16().unwrap();
        let authority_count = bytes.read_u16().unwrap();
        let additional_count = bytes.read_u16().unwrap();

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

    /// Converts a Header to a byte stream.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.id.to_be_bytes());

        let codes1 = {
            let mut byte = 0000_0000;
            byte |= (self.is_response as u8) << 7;
            byte |= self.op_code << 3;
            byte |= (self.is_authority as u8) << 2;
            byte |= (self.is_truncated as u8) << 1;
            byte |= (self.recursion_desired as u8) << 0;
            byte
        };
        bytes.push(codes1);

        let codes2 = {
            let mut byte = 0;
            byte |= (self.recursion_available as u8) << 7;
            byte |= self.resp_code as u8;
            byte
        };
        bytes.push(codes2);

        bytes.extend(self.question_count.to_be_bytes());
        bytes.extend(self.answer_count.to_be_bytes());
        bytes.extend(self.authority_count.to_be_bytes());
        bytes.extend(self.additional_count.to_be_bytes());

        bytes
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
        labels.push("".to_string());

        let name = labels.join(".");

        let q_type = bytes.read_u16().unwrap();
        let q_class = bytes.read_u16().unwrap();

        Self {
            name,
            q_type,
            q_class,
        }
    }

    /// Converts a Question to a byte stream.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        for label in self.name.split(".") {
            if label == "" {
                bytes.push(0);
                break;
            }
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }

        bytes.extend(self.q_type.to_be_bytes());
        bytes.extend(self.q_class.to_be_bytes());

        bytes
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

    /// Reads a u16 from the buffer.
    ///
    /// Returns None if the end of the buffer has been reached.
    fn read_u16(&mut self) -> Option<u16> {
        self.read_exact(2)
            .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a u32 from the buffer.
    ///
    /// Returns None if the end of the buffer has been reached.
    fn read_u32(&mut self) -> Option<u32> {
        self.read_exact(4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
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
