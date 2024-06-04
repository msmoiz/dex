use std::{
    fmt::Display,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use serde::{de::Visitor, Deserialize};

fn main() {
    Server::start();
}

/// A DNS server.
struct Server {
    zone: Zone,
}

impl Server {
    /// Starts a new DNS server.
    fn start() {
        let zone_file = "zone.toml";
        println!("loading zone data from {zone_file}");
        let zone_data = fs::read_to_string(zone_file).unwrap();
        let zone = Zone::from_toml(&zone_data).unwrap();
        let server = Self { zone };

        println!("listening on port 5380");
        let socket = std::net::UdpSocket::bind("0.0.0.0:5380").unwrap();
        loop {
            let mut q_buf = [0; 512];
            let (_, addr) = socket.recv_from(&mut q_buf).unwrap();
            println!("received query from {addr}");
            let mut q_bytes = Bytes::from_buf(&q_buf);
            let query = Message::from_bytes(&mut q_bytes);
            let response = server.serve(query);
            let r_bytes = response.to_bytes();
            socket.send_to(&r_bytes, addr).unwrap();
            println!("returned response to sender");
        }
    }

    /// Serves a DNS query.
    ///
    /// Returns a DNS response.
    fn serve(&self, query: Message) -> Message {
        let mut response = query;
        response.header.is_response = true;

        let question = &response.questions[0];
        println!("question: {} {:?}", question.name, question.q_type);

        if !matches!(response.header.op_code, OperationCode::Query) {
            response.header.resp_code = ResponseCode::NotImplemented;
            println!("response: {:?}", response.header.resp_code);
            return response;
        }

        let matched_records: Vec<&_> = self
            .zone
            .records
            .iter()
            .filter(|r| r.name() == &question.name)
            .filter(|r| r.code() == question.q_type.code())
            .collect();

        if matched_records.len() > 0 {
            response.header.is_authority = true;
            response.header.resp_code = ResponseCode::Success;
            response.header.answer_count = matched_records.len() as u16;
            for record in matched_records {
                response.answer_records.push(record.clone());
            }
        } else {
            let ns_records: Vec<&_> = self
                .zone
                .records
                .iter()
                .filter(|r| matches!(r, Record::Ns { .. }))
                .filter(|r| r.name() != &self.zone.name)
                .filter(|r| r.name().contains(&question.name))
                .collect();

            if ns_records.len() > 0 {
                response.header.is_authority = true;
                response.header.resp_code = ResponseCode::Success;
                response.header.authority_count = ns_records.len() as u16;
                for record in ns_records {
                    response.authority_records.push(record.clone());
                }
            } else {
                response.header.resp_code = ResponseCode::NameError;
            }
        }

        println!("response: {:?}", response.header.resp_code);
        response
    }
}

/// A fully qualified DNS domain name.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Name {
    labels: Vec<String>,
}

impl Name {
    /// Creates a Name from a string.
    fn from_str(input: &str) -> Self {
        let labels = input.split(".").map(|s| s.to_string()).collect();
        Self { labels }
    }

    /// Creates a Name from a byte stream.
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

        Self { labels }
    }

    /// Returns true if this name "contains" the other name.
    ///
    /// Returns true if the other name is a subdomain of this name. This also
    /// returns true when the name and the other name are equal.
    fn contains(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }

        let mut this = self.labels.iter().rev(); //     example.com.
        let mut other = other.labels.iter().rev(); // sub.example.com.
        loop {
            match (this.next(), other.next()) {
                (Some(t), Some(o)) if t == o => continue,
                (Some(_), Some(_)) => return false,
                (Some(_), None) => return false,
                (None, Some(_)) => return true,
                (None, None) => return true,
            }
        }
    }

    /// Converts a Name to a byte stream.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        for label in &self.labels {
            if label == "" {
                bytes.push(0);
                break;
            }
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }

        bytes
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.labels.join("."))
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NameVisitor;

        impl<'de> Visitor<'de> for NameVisitor {
            type Value = Name;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a fully-qualified domain name")
            }

            fn visit_str<E>(self, v: &str) -> std::prelude::v1::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let labels: Vec<_> = v.split(".").map(|s| s.to_owned()).collect();

                match labels.last() {
                    Some(label) if label != "" => {
                        return Err(serde::de::Error::invalid_value(
                            serde::de::Unexpected::Str(v),
                            &self,
                        ));
                    }
                    None => {
                        return Err(serde::de::Error::invalid_value(
                            serde::de::Unexpected::Str(v),
                            &self,
                        ))
                    }
                    _ => {}
                };

                Ok(Name { labels })
            }
        }

        deserializer.deserialize_str(NameVisitor)
    }
}

/// A DNS resource record.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
enum Record {
    /// IPv4 address record.
    A {
        name: Name,
        class: Class,
        ttl: u32,
        addr: Ipv4Addr,
    },
    /// Name server record.
    Ns {
        name: Name,
        class: Class,
        ttl: u32,
        host: Name,
    },
    /// Canonical name record.
    Cname {
        name: Name,
        class: Class,
        ttl: u32,
        host: Name,
    },
    /// Mail exchange record.
    Mx {
        name: Name,
        class: Class,
        ttl: u32,
        priority: u16,
        host: Name,
    },
    /// Text record.
    Txt {
        name: Name,
        class: Class,
        ttl: u32,
        content: String,
    },
    /// IPv6 address record.
    Aaaa {
        name: Name,
        class: Class,
        ttl: u32,
        addr: Ipv6Addr,
    },
}

impl Record {
    /// Creates a Record from a byte stream.
    fn from_bytes(bytes: &mut Bytes) -> Self {
        let name = Name::from_bytes(bytes);
        let r_type = bytes.read_u16().unwrap();
        let class = bytes.read_u16().unwrap().into();
        let ttl = bytes.read_u32().unwrap();
        let _rd_len = bytes.read_u16().unwrap();

        // @todo: support all types
        match r_type {
            1 => {
                let addr = bytes.read_u32().unwrap().into();

                Self::A {
                    name,
                    class,
                    ttl,
                    addr,
                }
            }
            2 => {
                let host = Name::from_bytes(bytes);

                Self::Ns {
                    name,
                    class,
                    ttl,
                    host,
                }
            }
            _ => todo!(),
        }
    }

    /// Returns the name of the record.
    fn name(&self) -> &Name {
        match self {
            Record::A { name, .. } => name,
            Record::Ns { name, .. } => name,
            Record::Cname { name, .. } => name,
            Record::Mx { name, .. } => name,
            Record::Txt { name, .. } => name,
            Record::Aaaa { name, .. } => name,
        }
    }

    /// Returns the class of the record.
    fn class(&self) -> Class {
        match self {
            Record::A { class, .. } => class,
            Record::Ns { class, .. } => class,
            Record::Cname { class, .. } => class,
            Record::Mx { class, .. } => class,
            Record::Txt { class, .. } => class,
            Record::Aaaa { class, .. } => class,
        }
        .clone()
    }

    /// Returns the ttl of the record.
    fn ttl(&self) -> u32 {
        *match self {
            Record::A { ttl, .. } => ttl,
            Record::Ns { ttl, .. } => ttl,
            Record::Cname { ttl, .. } => ttl,
            Record::Mx { ttl, .. } => ttl,
            Record::Txt { ttl, .. } => ttl,
            Record::Aaaa { ttl, .. } => ttl,
        }
    }

    /// Returns the code of the record.
    fn code(&self) -> u16 {
        match self {
            Record::A { .. } => 1,
            Record::Ns { .. } => 2,
            Record::Cname { .. } => 5,
            Record::Mx { .. } => 15,
            Record::Txt { .. } => 16,
            Record::Aaaa { .. } => 28,
        }
    }

    /// Converts a Record to a byte stream.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.name().to_bytes());
        bytes.extend(self.code().to_be_bytes());
        bytes.extend(u16::from(self.class()).to_be_bytes());
        bytes.extend(self.ttl().to_be_bytes());

        // @todo: support all types
        match self {
            Record::A { addr, .. } => {
                bytes.extend((4 as u16).to_be_bytes());
                bytes.extend(addr.octets());
            }
            Record::Ns { host, .. } => {
                let host = host.to_bytes();
                bytes.extend((host.len() as u16).to_be_bytes());
                bytes.extend(host);
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
            Record::Ns { host, .. } => write!(f, "NS {host}"),
            Record::Cname { host, .. } => write!(f, "CNAME {host}"),
            Record::Mx { priority, host, .. } => write!(f, "MX {priority} {host}"),
            Record::Txt { content, .. } => write!(f, "TXT {content}"),
            Record::Aaaa { addr, .. } => write!(f, "AAAA {addr}"),
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
    /// Name of the zone.
    name: Name,
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

/// A DNS operation code.
#[derive(Debug, Clone)]
enum OperationCode {
    /// A standard query.
    Query,
    /// An inverse query.
    InverseQuery,
    /// A server status request.
    Status,
}

impl From<u8> for OperationCode {
    fn from(value: u8) -> Self {
        use OperationCode::*;

        match value {
            0 => Query,
            1 => InverseQuery,
            2 => Status,
            _ => panic!("unsupported operation code: {value}"),
        }
    }
}

impl From<OperationCode> for u8 {
    fn from(value: OperationCode) -> Self {
        use OperationCode::*;

        match value {
            Query => 0,
            InverseQuery => 1,
            Status => 2,
        }
    }
}

/// A DNS response code.
#[derive(Debug, Clone)]
enum ResponseCode {
    /// No error condition.
    Success,
    /// The name server was unable to interpret the query.
    FormatError,
    /// The name server was unable to process the query due to a problem with
    /// the name server.
    ServerFailure,
    /// The domain name referenced in the query does not exist.
    NameError,
    /// The name server does not support the request kind of query.
    NotImplemented,
    /// The name server refuses to perform the specified operation for policy reasons.
    Refused,
}

impl From<u8> for ResponseCode {
    fn from(value: u8) -> Self {
        use ResponseCode::*;

        match value {
            0 => Success,
            1 => FormatError,
            2 => ServerFailure,
            3 => NameError,
            4 => NotImplemented,
            5 => Refused,
            _ => panic!("unsupported response code: {value}"),
        }
    }
}

impl From<ResponseCode> for u8 {
    fn from(value: ResponseCode) -> Self {
        use ResponseCode::*;

        match value {
            Success => 0,
            FormatError => 1,
            ServerFailure => 2,
            NameError => 3,
            NotImplemented => 4,
            Refused => 5,
        }
    }
}

/// Message header.
#[derive(Debug)]
struct Header {
    id: u16,
    is_response: bool,
    op_code: OperationCode,
    is_authority: bool,
    is_truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    resp_code: ResponseCode,
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
                op_code.into(),
                is_authority,
                is_truncated,
                recursion_desired,
            )
        };

        let (recursion_available, resp_code) = {
            let byte = bytes.read().unwrap();
            let recursion_available = ((byte >> 7) & 1) == 1;
            let resp_code = byte & 0b1111;
            (recursion_available, resp_code.into())
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
            byte |= u8::from(self.op_code.clone()) << 3;
            byte |= (self.is_authority as u8) << 2;
            byte |= (self.is_truncated as u8) << 1;
            byte |= (self.recursion_desired as u8) << 0;
            byte
        };
        bytes.push(codes1);

        let codes2 = {
            let mut byte = 0;
            byte |= (self.recursion_available as u8) << 7;
            byte |= u8::from(self.resp_code.clone());
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

/// The type of a DNS question.
#[derive(Debug, Clone)]
enum QuestionType {
    /// A host address.
    A,
    /// An authoritative name server.
    NS,
    /// A mail destination (deprecated in favor of MX).
    MD,
    /// A mail forwarder (deprecated in favor of MX).
    MF,
    /// The canonical name for an alias.
    CNAME,
    /// Marks the start of a zone of authority.
    SOA,
    /// A mailbox domain name (experimental).
    MB,
    /// A mail group member (experimental).
    MG,
    /// A mail rename domain name (experimental).
    MR,
    /// A null record (experimental).
    NULL,
    /// A well known service description.
    WKS,
    /// A domain name pointer.
    PTR,
    /// Host information.
    HINFO,
    /// Mailbox or mail list information.
    MINFO,
    /// Mail exchange.
    MX,
    /// Text strings.
    TXT,
    /// A request for a transfer of an entire zone.
    AXFR,
    /// A request for mailbox-related records (MB, MG or MR).
    MAILB,
    /// A request for mail agent records (deprecated in favor of MX).
    MAILA,
    /// A request for all records
    ALL,
}

impl QuestionType {
    /// Returns the code for this type.
    fn code(&self) -> u16 {
        self.clone().into()
    }
}

impl From<u16> for QuestionType {
    fn from(value: u16) -> Self {
        use QuestionType::*;

        match value {
            1 => A,
            2 => NS,
            3 => MD,
            4 => MF,
            5 => CNAME,
            6 => SOA,
            7 => MB,
            8 => MG,
            9 => MR,
            10 => NULL,
            11 => WKS,
            12 => PTR,
            13 => HINFO,
            14 => MINFO,
            15 => MX,
            16 => TXT,
            252 => AXFR,
            253 => MAILB,
            254 => MAILA,
            255 => ALL,
            _ => panic!("unsupported question type: {value}"),
        }
    }
}

impl From<QuestionType> for u16 {
    fn from(value: QuestionType) -> Self {
        use QuestionType::*;

        match value {
            A => 1,
            NS => 2,
            MD => 3,
            MF => 4,
            CNAME => 5,
            SOA => 6,
            MB => 7,
            MG => 8,
            MR => 9,
            NULL => 10,
            WKS => 11,
            PTR => 12,
            HINFO => 13,
            MINFO => 14,
            MX => 15,
            TXT => 16,
            AXFR => 252,
            MAILB => 253,
            MAILA => 254,
            ALL => 255,
        }
    }
}

/// The class of a DNS question.
#[derive(Debug, Clone)]
enum QuestionClass {
    /// Internet.
    In,
    /// CS Net.
    Cs,
    /// Chaos.
    Ch,
    /// Hesiod.
    Hs,
    /// Any.
    Any,
}

impl From<u16> for QuestionClass {
    fn from(value: u16) -> Self {
        use QuestionClass::*;

        match value {
            1 => In,
            2 => Cs,
            3 => Ch,
            4 => Hs,
            255 => Any,
            _ => panic!("unsupported question class: {value}"),
        }
    }
}

impl From<QuestionClass> for u16 {
    fn from(value: QuestionClass) -> Self {
        use QuestionClass::*;

        match value {
            In => 1,
            Cs => 2,
            Ch => 3,
            Hs => 4,
            Any => 255,
        }
    }
}

/// A DNS question.
#[derive(Debug)]
struct Question {
    name: Name,
    q_type: QuestionType,
    q_class: QuestionClass,
}

impl Question {
    /// Creates a Question from a byte stream.
    fn from_bytes(bytes: &mut Bytes) -> Self {
        let name = Name::from_bytes(bytes);
        let q_type = bytes.read_u16().unwrap().into();
        let q_class = bytes.read_u16().unwrap().into();

        Self {
            name,
            q_type,
            q_class,
        }
    }

    /// Converts a Question to a byte stream.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.name.to_bytes());
        bytes.extend(u16::from(self.q_type.clone()).to_be_bytes());
        bytes.extend(u16::from(self.q_class.clone()).to_be_bytes());

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
    use crate::{Name, Zone};

    #[test]
    fn parse_toml() {
        let input = r#"
            name = "example.com."

            [[records]]
            name = "example.com."
            class = "IN"
            ttl = 60
            type = "A"
            addr = "0.0.0.0"
        "#;

        let zone: Zone = Zone::from_toml(input).unwrap();
        assert_eq!(zone.records[0].name(), &Name::from_str("example.com."))
    }
}
