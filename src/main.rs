use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

fn main() {
    let records = [
        Record {
            name: "example.com".to_string(),
            kind: RecordKind::Txt("hello world!".to_string()),
            class: RecordClass::In,
            ttl: 60,
        },
        Record {
            name: "example.com".to_string(),
            kind: RecordKind::Mx(10, "smtp.example.com".to_string()),
            class: RecordClass::In,
            ttl: 60,
        },
    ];

    for record in records {
        println!("{record}")
    }
}

/// A DNS resource record.
#[derive(Debug)]
struct Record {
    /// The name of the node that the record pertains to.
    name: String,
    /// The type of the record.
    kind: RecordKind,
    /// The namespace of the record.
    class: RecordClass,
    /// The time that the record is valid.
    ttl: u32,
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {} {}", self.name, self.class, self.ttl, self.kind)
    }
}

#[derive(Debug)]
enum RecordKind {
    /// IPv4 address record.
    A(Ipv4Addr),
    /// IPv6 address record.
    Aaaa(Ipv6Addr),
    /// Canonical name record.
    Cname(String),
    /// Mail exchange record.
    Mx(u16, String),
    /// Name server record.
    Ns(String),
    /// Text record.
    Txt(String),
}

impl Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordKind::A(addr) => write!(f, "A {addr}"),
            RecordKind::Aaaa(addr) => write!(f, "AAAA {addr}"),
            RecordKind::Cname(host) => write!(f, "CNAME {host}"),
            RecordKind::Mx(priority, host) => write!(f, "MX {priority} {host}"),
            RecordKind::Ns(ns) => write!(f, "NS {ns}"),
            RecordKind::Txt(text) => write!(f, "TXT {text}"),
        }
    }
}

#[derive(Default, Debug)]
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
