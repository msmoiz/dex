use std::{
    fmt::Display,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
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
            let mut query_buffer = [0; 512];
            let (_, addr) = socket.recv_from(&mut query_buffer).unwrap();
            println!("received query from {addr}");

            let mut query_bytes = Bytes::from_buf(query_buffer);
            let query = Message::from_bytes(&mut query_bytes);

            let response = server.serve(query);
            println!("response: {:?}", response.header.resp_code);

            let mut response_bytes = Bytes::new();
            response.to_bytes(&mut response_bytes);
            socket.send_to(response_bytes.used(), addr).unwrap();

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

        for qname in question.name.ancestors() {
            let name_records = self.zone.find_with_name(&qname);

            // leaf
            if qname == question.name {
                // check for cname
                if let Some(cname_record) = name_records
                    .iter()
                    .find(|r| matches!(r, Record::Cname { .. }))
                {
                    response.header.is_authority = true;
                    response.header.resp_code = ResponseCode::Success;
                    response.header.answer_count = 1;
                    response.answer_records.push((*cname_record).clone());
                    return response;
                }

                // check for exact matches
                let matched_records: Vec<_> = name_records
                    .iter()
                    .filter(|r| {
                        r.code() == question.q_type.code()
                            || matches!(question.q_type, QuestionType::ALL)
                    })
                    .collect();

                if !matched_records.is_empty() {
                    response.header.is_authority = true;
                    response.header.resp_code = ResponseCode::Success;
                    response.header.answer_count = matched_records.len() as u16;
                    for record in matched_records {
                        response.answer_records.push((*record).clone());
                    }
                    return response;
                }
            }

            // leaf or ancestor: check for delegation
            let delegation_records: Vec<_> = name_records
                .iter()
                .filter(|r| matches!(r, Record::Ns { .. }))
                .collect();

            if !delegation_records.is_empty() {
                response.header.is_authority = false;
                response.header.resp_code = ResponseCode::Success;
                response.header.authority_count = delegation_records.len() as u16;
                for record in delegation_records {
                    response.authority_records.push((*record).clone());
                }
                return response;
            }
        }

        response.header.resp_code = ResponseCode::NameError;
        response
    }
}

/// A DNS label.
///
/// A label must be shorter than 63 bytes.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Label(String);

impl Label {
    /// Creates a new Label from a string.
    fn from_str(text: &str) -> Self {
        assert!(text.len() < 63);

        lazy_static! {
            static ref RE: Regex =
                Regex::new("^[[:alpha:]]([[:alpha:]0-9-]*[[:alpha:]0-9])?$").unwrap();
        }

        assert!(text.is_empty() || RE.is_match(text));

        Self(text.to_owned())
    }

    /// Creates a new Label from a byte stream.
    fn from_bytes(bytes: &mut Bytes) -> Self {
        let len = bytes.read().unwrap();
        let bytez = bytes.read_exact(len as usize).unwrap();
        let text = String::from_utf8(bytez).unwrap();
        Self::from_str(&text)
    }

    /// Converts a Label to a byte stream.
    fn to_bytes(&self, bytes: &mut Bytes) {
        bytes.write(self.0.len() as u8);
        bytes.write_all(self.0.as_bytes());
    }

    /// Returns the length of the label.
    fn len(&self) -> u8 {
        self.0.len() as u8
    }
}

/// A fully qualified DNS domain name.
///
/// A name must be shorter than 255 bytes. The last label in a name must be the
/// root label ("") and all other labels must non-empty.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Name {
    labels: Vec<Label>,
}

impl Name {
    /// Creates a Name from labels.
    fn from_labels(labels: Vec<Label>) -> Self {
        assert!(!labels.is_empty());

        let len = labels.len() + labels.iter().fold(0, |acc, l| acc + l.len() as usize);
        assert!(len < 255);

        let Some((last, rest)) = labels.split_last() else {
            unreachable!()
        };

        assert_eq!(last.0, "");
        for label in rest {
            assert_ne!(label.0, "");
        }

        Self { labels }
    }

    /// Creates a Name from a string.
    fn from_str(input: &str) -> Self {
        let labels = input.split(".").map(|s| Label::from_str(s)).collect();
        Self::from_labels(labels)
    }

    /// Creates a Name from a byte stream.
    fn from_bytes(bytes: &mut Bytes) -> Self {
        let mut labels = vec![];

        let mut restore: Option<usize> = None;
        let mut max = bytes.pos();
        loop {
            let signal = bytes.peek().unwrap();
            let is_ptr = (signal >> 6 & 3) == 3;
            if is_ptr {
                let ptr = bytes.read_u16().unwrap();
                let offset = ptr & 0b0011_1111_1111_1111;

                if offset as usize >= max {
                    panic!("detected pointer loop")
                }

                if restore.is_none() {
                    restore = Some(bytes.pos);
                }

                bytes.seek(offset as usize);
                max = offset as usize;
            } else {
                let label = Label::from_bytes(bytes);
                let is_root = label.len() == 0;
                labels.push(label);
                if is_root {
                    break;
                }
            }
        }

        if let Some(restore) = restore {
            bytes.seek(restore);
        }

        Self::from_labels(labels)
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
    fn to_bytes(&self, bytes: &mut Bytes) {
        for label in &self.labels {
            label.to_bytes(bytes);
        }
    }

    /// Returns an iterator over the ancestors of this name.
    ///
    /// Ancestors are returned in ascending order based on length. The last
    /// element returned is the full name.
    fn ancestors(&self) -> Ancestors {
        Ancestors::new(self)
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for label in &self.labels {
            write!(f, "{}", label.0)?;
            if label.0 != "" {
                write!(f, ".")?;
            }
        }
        Ok(())
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
                let labels: Vec<_> = v.split(".").map(|s| Label::from_str(s)).collect();

                match labels.last() {
                    Some(label) if label.0 != "" => {
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

                Ok(Name::from_labels(labels))
            }
        }

        deserializer.deserialize_str(NameVisitor)
    }
}

/// Iterator over the ancestors of a name.
struct Ancestors<'a> {
    name: &'a Name,
    pos: usize,
}

impl<'a> Ancestors<'a> {
    fn new(name: &'a Name) -> Self {
        Self { name, pos: 1 }
    }
}

impl<'a> Iterator for Ancestors<'a> {
    type Item = Name;

    fn next(&mut self) -> Option<Self::Item> {
        let len = self.name.labels.len();

        if self.pos > len {
            return None;
        }

        let ancestor = &self.name.labels[len - self.pos..];
        let ancestor: Vec<_> = ancestor.iter().cloned().collect();
        self.pos += 1;

        Some(Name::from_labels(ancestor))
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
    /// Mail destination record.
    Md {
        name: Name,
        class: Class,
        ttl: u32,
        host: Name,
    },
    /// Mail forwarded record.
    Mf {
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
    /// Statement of authority record.
    Soa {
        name: Name,
        class: Class,
        ttl: u32,
        origin: Name,
        mailbox: Name,
        version: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// Mailbox domain record.
    Mb {
        name: Name,
        class: Class,
        ttl: u32,
        host: Name,
    },
    /// Mail group record.
    Mg {
        name: Name,
        class: Class,
        ttl: u32,
        host: Name,
    },
    /// Mail rename record.
    Mr {
        name: Name,
        class: Class,
        ttl: u32,
        host: Name,
    },
    /// Null record.
    Null {
        name: Name,
        class: Class,
        ttl: u32,
        data: Vec<u8>,
    },
    /// Well known service record.
    Wks {
        name: Name,
        class: Class,
        ttl: u32,
        addr: Ipv4Addr,
        protocol: u8,
        data: Vec<u8>,
    },
    /// Domain name pointer record.
    Ptr {
        name: Name,
        class: Class,
        ttl: u32,
        host: Name,
    },
    /// Host information record.
    Hinfo {
        name: Name,
        class: Class,
        ttl: u32,
        cpu: String,
        os: String,
    },
    /// Mailbox information record.
    Minfo {
        name: Name,
        class: Class,
        ttl: u32,
        r_mailbox: Name,
        e_mailbox: Name,
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
        let rd_len = bytes.read_u16().unwrap();

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
            3 => {
                let host = Name::from_bytes(bytes);

                Self::Md {
                    name,
                    class,
                    ttl,
                    host,
                }
            }
            4 => {
                let host = Name::from_bytes(bytes);

                Self::Mf {
                    name,
                    class,
                    ttl,
                    host,
                }
            }
            5 => {
                let host = Name::from_bytes(bytes);

                Self::Cname {
                    name,
                    class,
                    ttl,
                    host,
                }
            }
            6 => {
                let origin = Name::from_bytes(bytes);
                let mailbox = Name::from_bytes(bytes);
                let version = bytes.read_u32().unwrap();
                let refresh = bytes.read_u32().unwrap();
                let retry = bytes.read_u32().unwrap();
                let expire = bytes.read_u32().unwrap();
                let minimum = bytes.read_u32().unwrap();

                Self::Soa {
                    name,
                    class,
                    ttl,
                    origin,
                    mailbox,
                    version,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            7 => {
                let host = Name::from_bytes(bytes);

                Self::Mb {
                    name,
                    class,
                    ttl,
                    host,
                }
            }
            8 => {
                let host = Name::from_bytes(bytes);

                Self::Mg {
                    name,
                    class,
                    ttl,
                    host,
                }
            }
            9 => {
                let host = Name::from_bytes(bytes);

                Self::Mr {
                    name,
                    class,
                    ttl,
                    host,
                }
            }
            10 => {
                let data = bytes.read_exact(rd_len as usize).unwrap();

                Self::Null {
                    name,
                    class,
                    ttl,
                    data,
                }
            }
            11 => {
                let addr = Ipv4Addr::from(bytes.read_u32().unwrap());
                let protocol = bytes.read().unwrap();
                let data = {
                    let len = rd_len as usize - 5;
                    let bytez = bytes.read_exact(len).unwrap();
                    bytez
                };

                Self::Wks {
                    name,
                    class,
                    ttl,
                    addr,
                    protocol,
                    data,
                }
            }
            12 => {
                let host = Name::from_bytes(bytes);

                Self::Ptr {
                    name,
                    class,
                    ttl,
                    host,
                }
            }
            13 => {
                let cpu = {
                    let len = bytes.read().unwrap();
                    let bytez = bytes.read_exact(len as usize).unwrap();
                    String::from_utf8(bytez).unwrap()
                };

                let os = {
                    let len = bytes.read().unwrap();
                    let bytez = bytes.read_exact(len as usize).unwrap();
                    String::from_utf8(bytez).unwrap()
                };

                Self::Hinfo {
                    name,
                    class,
                    ttl,
                    cpu,
                    os,
                }
            }
            14 => {
                let r_mailbox = Name::from_bytes(bytes);
                let e_mailbox = Name::from_bytes(bytes);

                Self::Minfo {
                    name,
                    class,
                    ttl,
                    r_mailbox,
                    e_mailbox,
                }
            }
            15 => {
                let priority = bytes.read_u16().unwrap();
                let host = Name::from_bytes(bytes);

                Self::Mx {
                    name,
                    class,
                    ttl,
                    priority,
                    host,
                }
            }
            16 => {
                let content = {
                    let mut buf = vec![];
                    let mut read = 0;
                    while read < rd_len {
                        let len = bytes.read().unwrap();
                        let bytez = bytes.read_exact(len as usize).unwrap();
                        buf.extend(bytez);
                        read += (len as u16) + 1;
                    }
                    String::from_utf8(buf).unwrap()
                };

                Self::Txt {
                    name,
                    class,
                    ttl,
                    content,
                }
            }
            28 => {
                let addr = {
                    let bytez = bytes.read_exact(16).unwrap();
                    let bytez: [u8; 16] = bytez.try_into().unwrap();
                    Ipv6Addr::from(bytez)
                };

                Self::Aaaa {
                    name,
                    class,
                    ttl,
                    addr,
                }
            }
            _ => panic!("unsupported record type: {r_type}"),
        }
    }

    /// Returns the name of the record.
    fn name(&self) -> &Name {
        match self {
            Record::A { name, .. } => name,
            Record::Ns { name, .. } => name,
            Record::Md { name, .. } => name,
            Record::Mf { name, .. } => name,
            Record::Cname { name, .. } => name,
            Record::Soa { name, .. } => name,
            Record::Mb { name, .. } => name,
            Record::Mg { name, .. } => name,
            Record::Mr { name, .. } => name,
            Record::Null { name, .. } => name,
            Record::Wks { name, .. } => name,
            Record::Ptr { name, .. } => name,
            Record::Hinfo { name, .. } => name,
            Record::Minfo { name, .. } => name,
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
            Record::Md { class, .. } => class,
            Record::Mf { class, .. } => class,
            Record::Cname { class, .. } => class,
            Record::Soa { class, .. } => class,
            Record::Mb { class, .. } => class,
            Record::Mg { class, .. } => class,
            Record::Mr { class, .. } => class,
            Record::Null { class, .. } => class,
            Record::Wks { class, .. } => class,
            Record::Ptr { class, .. } => class,
            Record::Hinfo { class, .. } => class,
            Record::Minfo { class, .. } => class,
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
            Record::Md { ttl, .. } => ttl,
            Record::Mf { ttl, .. } => ttl,
            Record::Cname { ttl, .. } => ttl,
            Record::Soa { ttl, .. } => ttl,
            Record::Mb { ttl, .. } => ttl,
            Record::Mg { ttl, .. } => ttl,
            Record::Mr { ttl, .. } => ttl,
            Record::Null { ttl, .. } => ttl,
            Record::Wks { ttl, .. } => ttl,
            Record::Ptr { ttl, .. } => ttl,
            Record::Hinfo { ttl, .. } => ttl,
            Record::Minfo { ttl, .. } => ttl,
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
            Record::Md { .. } => 3,
            Record::Mf { .. } => 4,
            Record::Cname { .. } => 5,
            Record::Soa { .. } => 6,
            Record::Mb { .. } => 7,
            Record::Mg { .. } => 8,
            Record::Mr { .. } => 9,
            Record::Null { .. } => 10,
            Record::Wks { .. } => 11,
            Record::Ptr { .. } => 12,
            Record::Hinfo { .. } => 13,
            Record::Minfo { .. } => 14,
            Record::Mx { .. } => 15,
            Record::Txt { .. } => 16,
            Record::Aaaa { .. } => 28,
        }
    }

    /// Converts a Record to a byte stream.
    fn to_bytes(&self, bytes: &mut Bytes) {
        self.name().to_bytes(bytes);
        bytes.write_u16(self.code());
        bytes.write_u16(u16::from(self.class()));
        bytes.write_u32(self.ttl());

        match self {
            Record::A { addr, .. } => {
                bytes.write_u16(4);
                bytes.write_all(&addr.octets());
            }
            Record::Ns { host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Md { host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Mf { host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Cname { host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Soa {
                origin,
                mailbox,
                version,
                refresh,
                retry,
                expire,
                minimum,
                ..
            } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                origin.to_bytes(bytes);
                mailbox.to_bytes(bytes);
                bytes.write_u32(*version);
                bytes.write_u32(*refresh);
                bytes.write_u32(*retry);
                bytes.write_u32(*expire);
                bytes.write_u32(*minimum);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Mb { host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Mg { host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Mr { host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Null { data, .. } => {
                bytes.write_u16(data.len() as u16);
                bytes.write_all(data);
            }
            Record::Wks {
                addr,
                protocol,
                data,
                ..
            } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                bytes.write_all(&addr.octets());
                bytes.write(*protocol);
                bytes.write_all(data);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Ptr { host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Hinfo { cpu, os, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                bytes.write(cpu.len() as u8);
                bytes.write_all(cpu.as_bytes());
                bytes.write(os.len() as u8);
                bytes.write_all(os.as_bytes());

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Minfo {
                r_mailbox,
                e_mailbox,
                ..
            } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                r_mailbox.to_bytes(bytes);
                e_mailbox.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Mx { priority, host, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                bytes.write_u16(*priority);
                host.to_bytes(bytes);

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Txt { content, .. } => {
                let pos = bytes.pos();
                bytes.write_u16(0);

                let bytez = content.as_bytes();
                let chunks = bytez.chunks(255);
                for chunk in chunks {
                    bytes.write(chunk.len() as u8);
                    bytes.write_all(chunk);
                }

                let size = bytes.pos() - (pos + 2);
                bytes.set_u16(pos, size as u16);
            }
            Record::Aaaa { addr, .. } => {
                bytes.write_u16(16);
                bytes.write_all(&addr.octets());
            }
        }
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {} ", self.name(), self.class(), self.ttl())?;
        match self {
            Record::A { addr, .. } => write!(f, "A {addr}"),
            Record::Ns { host, .. } => write!(f, "NS {host}"),
            Record::Md { host, .. } => write!(f, "MD {host}"),
            Record::Mf { host, .. } => write!(f, "MF {host}"),
            Record::Cname { host, .. } => write!(f, "CNAME {host}"),
            Record::Soa {
                origin,
                mailbox,
                version,
                refresh,
                retry,
                expire,
                minimum,
                ..
            } => write!(
                f,
                "SOA {origin} {mailbox} {version} {refresh} {retry} {expire} {minimum}"
            ),
            Record::Mb { host, .. } => write!(f, "MB {host}"),
            Record::Mg { host, .. } => write!(f, "MG {host}"),
            Record::Mr { host, .. } => write!(f, "MR {host}"),
            Record::Null { data, .. } => write!(f, "NULL {data:x?}"),
            Record::Wks {
                addr,
                protocol,
                data,
                ..
            } => write!(f, "WKS {addr} {protocol} {data:x?}"),
            Record::Ptr { host, .. } => write!(f, "PTR {host}"),
            Record::Hinfo { cpu, os, .. } => write!(f, "HINFO {cpu} {os}"),
            Record::Minfo {
                r_mailbox,
                e_mailbox,
                ..
            } => write!(f, "MINFO {r_mailbox} {e_mailbox}"),
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

    /// Returns records with the specified name.
    fn find_with_name(&self, name: &Name) -> Vec<&Record> {
        self.records.iter().filter(|r| r.name() == name).collect()
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
    fn to_bytes(&self, bytes: &mut Bytes) {
        self.header.to_bytes(bytes);

        for question in &self.questions {
            question.to_bytes(bytes);
        }

        for record in &self.answer_records {
            record.to_bytes(bytes);
        }

        for record in &self.authority_records {
            record.to_bytes(bytes);
        }

        for record in &self.additional_records {
            record.to_bytes(bytes);
        }
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
    fn to_bytes(&self, bytes: &mut Bytes) {
        bytes.write_u16(self.id);

        let codes1 = {
            let mut byte = 0000_0000;
            byte |= (self.is_response as u8) << 7;
            byte |= u8::from(self.op_code.clone()) << 3;
            byte |= (self.is_authority as u8) << 2;
            byte |= (self.is_truncated as u8) << 1;
            byte |= (self.recursion_desired as u8) << 0;
            byte
        };
        bytes.write(codes1);

        let codes2 = {
            let mut byte = 0;
            byte |= (self.recursion_available as u8) << 7;
            byte |= u8::from(self.resp_code.clone());
            byte
        };
        bytes.write(codes2);

        bytes.write_u16(self.question_count);
        bytes.write_u16(self.answer_count);
        bytes.write_u16(self.authority_count);
        bytes.write_u16(self.additional_count);
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
    fn to_bytes(&self, bytes: &mut Bytes) {
        self.name.to_bytes(bytes);
        bytes.write_u16(u16::from(self.q_type.clone()));
        bytes.write_u16(u16::from(self.q_class.clone()));
    }
}

/// A byte stream.
struct Bytes {
    buf: [u8; 512],
    pos: usize,
}

impl Bytes {
    /// Creates a new Bytes iterator with an empty buffer.
    fn new() -> Self {
        Self {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Creates a new Bytes iterator from a buffer.
    fn from_buf(buf: [u8; 512]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the current position in the buffer.
    fn pos(&self) -> usize {
        self.pos
    }

    /// Returns a slice that represents the read (or written) bytes.
    fn used(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Returns a slice that represents the unread (or unwritten) bytes.
    fn remainder(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Seeks to a position in the buffer.
    fn seek(&mut self, pos: usize) {
        self.pos = pos;
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

    /// Reads the next byte from the buffer without advancing the position.
    ///
    /// Returns None if the end of the buffer has been reached.
    fn peek(&mut self) -> Option<u8> {
        if self.remainder().len() == 0 {
            return None;
        }
        let byte = self.remainder()[0];
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

    /// Writes a byte to the buffer.
    fn write(&mut self, byte: u8) {
        self.buf[self.pos] = byte;
        self.pos += 1;
    }

    /// Writes multiple bytes to the buffer.
    fn write_all(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write(*byte);
        }
    }

    /// Writes a u16 to the buffer.
    fn write_u16(&mut self, num: u16) {
        self.write_all(&num.to_be_bytes());
    }

    /// Writes a u32 to the buffer.
    fn write_u32(&mut self, num: u32) {
        self.write_all(&num.to_be_bytes());
    }

    /// Sets a byte in the buffer at a specific position.
    fn set(&mut self, pos: usize, byte: u8) {
        self.buf[pos] = byte;
    }

    /// Sets multiple bytes in the buffer starting at a specific position.
    fn set_all(&mut self, pos: usize, bytes: &[u8]) {
        for (i, byte) in bytes.iter().enumerate() {
            self.set(pos + i, *byte);
        }
    }

    /// Sets a u16 in the buffer at a specific position.
    fn set_u16(&mut self, pos: usize, num: u16) {
        self.set_all(pos, &num.to_be_bytes());
    }

    /// Sets a u32 in the buffer at a specific position.
    fn set_u32(&mut self, pos: usize, num: u32) {
        self.set_all(pos, &num.to_be_bytes());
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

    #[test]
    fn ancestors_iterate() {
        let name = Name::from_str("example.com.");
        let mut ancestors = name.ancestors();
        assert_eq!(ancestors.next(), Some(Name::from_str("")));
        assert_eq!(ancestors.next(), Some(Name::from_str("com.")));
        assert_eq!(ancestors.next(), Some(Name::from_str("example.com.")));
    }
}
