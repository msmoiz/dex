use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use serde::Deserialize;

fn main() {
    let zone_file = r#"
        [[records]]
        name = "example.com."
        class = "IN"
        ttl = 60
        type = "TXT"
        content = "hello world!"

        [[records]]
        name = "example.com."
        class = "IN"
        ttl = 86400
        type = "MX"
        priority = 10
        host = "mail.example.com."
    "#;

    let zone = Zone::from_toml(&zone_file).unwrap();

    for record in &zone.records {
        println!("{record}")
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
