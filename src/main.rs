use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use anyhow::{bail, Result};

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
#[derive(Debug, PartialEq, Eq, Clone)]
struct Record {
    /// The name of the domain that the record pertains to.
    name: String,
    /// The type of the record.
    kind: RecordKind,
    /// The namespace of the record.
    class: RecordClass,
    /// The time that the record is valid.
    ttl: u32,
}

impl Record {
    /// Creates a new Record.
    fn new(name: String, class: RecordClass, ttl: u32, kind: RecordKind) -> Self {
        Self {
            name,
            class,
            ttl,
            kind,
        }
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {} {}", self.name, self.class, self.ttl, self.kind)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[derive(Default, Debug, PartialEq, Eq, Clone)]
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
struct Zone {
    records: Vec<Record>,
}

impl Zone {
    /// Parse a Zone from an input in zone file format.
    ///
    /// The *zone file* format is defined in RFC 1035.
    fn from_str(input: &str) -> Self {
        ZoneParser::from_str(input).parse_zone().expect("todo")
    }
}

struct ZoneParser<'a> {
    input: &'a str,
    pos: usize,
    origin: Option<&'a str>,
    owner: Option<String>,
    ttl: Option<u32>,
    records: Vec<Record>,
}

impl<'a> ZoneParser<'a> {
    fn from_str(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            origin: None,
            owner: None,
            ttl: None,
            records: vec![],
        }
    }

    fn parse_zone(&mut self) -> Result<Zone> {
        while self.pos < self.input.len() {
            while self.scan_whitespace() || self.scan_newline() || self.scan_comment() {
                continue;
            }

            if let Some(origin) = self.parse_origin_dx()? {
                self.origin = Some(origin);
                continue;
            }

            if let Some(ttl) = self.parse_ttl_dx()? {
                self.ttl = Some(ttl);
                continue;
            }

            if let Some(record) = self.parse_record()? {
                self.owner = Some(record.name.clone());
                self.records.push(record);
            }
        }

        Ok(Zone {
            records: self.records.clone(),
        })
    }

    fn parse_origin_dx(&mut self) -> Result<Option<&'a str>> {
        let backup = self.pos;

        if !self.input[self.pos..].starts_with("$ORIGIN") {
            self.pos = backup;
            return Ok(None);
        }

        self.pos += 7;
        self.scan_whitespace();
        match self.scan_domain() {
            Some(domain) => Ok(Some(domain)),
            _ => bail!("missing domain for origin directive"),
        }
    }

    fn parse_ttl_dx(&mut self) -> Result<Option<u32>> {
        let backup = self.pos;

        self.scan_whitespace();
        if !self.input[self.pos..].starts_with("$TTL") {
            self.pos = backup;
            return Ok(None);
        }

        self.pos += 4;
        self.scan_whitespace();
        match self.scan_num() {
            Some(ttl) => Ok(Some(ttl)),
            _ => bail!("missing ttl for ttl directive"),
        }
    }

    fn parse_record(&mut self) -> Result<Option<Record>> {
        // 1. domain present
        if let Some(domain) = self.scan_domain() {
            self.scan_whitespace();

            // 1.1. ttl present
            if let Some(ttl) = self.scan_num() {
                self.scan_whitespace();

                // 1.1.1. class present
                if let Some(class) = self.scan_class() {
                    self.scan_whitespace();
                    let kind = self.parse_record_kind()?;
                    let record = Record::new(domain.into(), class, ttl, kind);
                    return Ok(Some(record));
                }

                // 1.1.2. class missing
                self.scan_whitespace();
                let kind = self.parse_record_kind()?;
                let class = RecordClass::In;
                let record = Record::new(domain.into(), class, ttl, kind);
                return Ok(Some(record));
            }

            // 1.2. class present
            if let Some(class) = self.scan_class() {
                self.scan_whitespace();

                // 1.2.1 ttl present
                if let Some(ttl) = self.scan_num() {
                    self.scan_whitespace();
                    let kind = self.parse_record_kind()?;
                    let record = Record::new(domain.into(), class, ttl, kind);
                    return Ok(Some(record));
                }

                // 1.2.2. ttl missing
                self.scan_whitespace();
                let kind = self.parse_record_kind()?;
                let ttl = 60;
                let record = Record::new(domain.into(), class, ttl, kind);
                return Ok(Some(record));
            }

            // 1.3. ttl and class missing
            let kind = self.parse_record_kind()?;
            let class = RecordClass::In;
            let ttl = 60;
            let record = Record::new(domain.into(), class, ttl, kind);
            return Ok(Some(record));
        }

        Ok(None)
    }

    fn parse_record_kind(&mut self) -> Result<RecordKind> {
        let Some(kind) = self.scan_alnum() else {
            bail!("unexpected end of record; missing type code");
        };

        self.scan_whitespace();

        match kind {
            "A" => self.parse_a_data(),
            "AAAA" => self.parse_aaaa_data(),
            "MX" => self.parse_mx_data(),
            "CNAME" => self.parse_cname_data(),
            "TXT" => self.parse_txt_data(),
            "NS" => self.parse_ns_data(),
            k @ _ => bail!("unsupported record type {k}"),
        }
    }

    fn parse_a_data(&mut self) -> Result<RecordKind> {
        let Some(ip) = self.scan_domain() else {
            bail!("missing ip address for A record");
        };
        let ip = Ipv4Addr::from_str(ip)?;
        Ok(RecordKind::A(ip))
    }

    fn parse_aaaa_data(&mut self) -> Result<RecordKind> {
        let Some(ip) = self.scan_ipv6() else {
            bail!("missing ip address for AAAA record");
        };
        let ip = Ipv6Addr::from_str(ip)?;
        Ok(RecordKind::Aaaa(ip))
    }

    fn parse_mx_data(&mut self) -> Result<RecordKind> {
        let Some(priority) = self.scan_num() else {
            bail!("missing priority for MX record");
        };
        self.scan_whitespace();
        let Some(name) = self.scan_domain() else {
            bail!("missing name for MX record");
        };
        Ok(RecordKind::Mx(priority as u16, name.into()))
    }

    fn parse_cname_data(&mut self) -> Result<RecordKind> {
        let Some(name) = self.scan_domain() else {
            bail!("missing name for CNAME record");
        };
        Ok(RecordKind::Cname(name.into()))
    }

    fn parse_txt_data(&mut self) -> Result<RecordKind> {
        let Some(data) = self.scan_alnum() else {
            bail!("missing data for TXT record");
        };
        Ok(RecordKind::Txt(data.into()))
    }

    fn parse_ns_data(&mut self) -> Result<RecordKind> {
        let Some(name) = self.scan_domain() else {
            bail!("missing name for NS record");
        };
        Ok(RecordKind::Ns(name.into()))
    }

    fn scan_whitespace(&mut self) -> bool {
        let mut len = 0;
        while len < self.remainder().len() {
            match self.input.as_bytes()[self.pos + len] {
                b' ' | b'\t' => len += 1,
                _ => break,
            }
        }

        self.pos += len;
        len > 0
    }

    fn scan_newline(&mut self) -> bool {
        let mut len = 0;
        while len < self.remainder().len() {
            match self.remainder().as_bytes()[len] {
                b'\r' | b'\n' => len += 1,
                _ => break,
            }
        }

        self.pos += len;
        len > 0
    }

    fn scan_comment(&mut self) -> bool {
        if !self.remainder().starts_with(";") {
            return false;
        }

        let mut len = 1;
        let mut chars = self.remainder()[len..].chars();
        while let Some(char) = chars.next() {
            match char {
                '\r' | '\n' => break,
                c @ _ => len += c.len_utf8(),
            }
        }

        self.pos += len;
        len > 0
    }

    fn scan_domain(&mut self) -> Option<&'a str> {
        let mut len = 0;
        let mut chars = self.remainder().chars();
        while let Some(char) = chars.next() {
            match char {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '.' => len += char.len_utf8(),
                _ => break,
            }
        }
        if len > 0 {
            let domain = &self.remainder()[..len];
            self.pos = self.pos + len;
            Some(&domain)
        } else {
            None
        }
    }

    fn scan_ipv6(&mut self) -> Option<&'a str> {
        let mut len = 0;
        let mut chars = self.remainder().chars();
        while let Some(char) = chars.next() {
            match char {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | ':' => len += char.len_utf8(),
                _ => break,
            }
        }
        if len > 0 {
            let domain = &self.remainder()[..len];
            self.pos = self.pos + len;
            Some(&domain)
        } else {
            None
        }
    }

    fn scan_num(&mut self) -> Option<u32> {
        let mut len = 0;
        let mut chars = self.remainder().chars();
        while let Some(char) = chars.next() {
            match char {
                '0'..='9' => len += char.len_utf8(),
                _ => break,
            }
        }
        if len > 0 {
            let num = self.remainder()[..len].parse().unwrap();
            self.pos = self.pos + len;
            Some(num)
        } else {
            None
        }
    }

    fn scan_class(&mut self) -> Option<RecordClass> {
        let start = self.remainder().chars().take(2).collect::<String>();
        let class = match start.as_ref() {
            "IN" => Some(RecordClass::In),
            "CH" => Some(RecordClass::Ch),
            "HS" => Some(RecordClass::Hs),
            _ => None,
        };

        if class.is_some() {
            self.pos += 2;
        }

        class
    }

    fn scan_alnum(&mut self) -> Option<&'a str> {
        let mut len = 0;
        let mut chars = self.remainder().chars();
        while let Some(char) = chars.next() {
            match char {
                'a'..='z' | 'A'..='Z' | '0'..='9' => len += char.len_utf8(),
                _ => break,
            }
        }
        if len > 0 {
            let alnum = &self.remainder()[..len];
            self.pos = self.pos + len;
            Some(alnum)
        } else {
            None
        }
    }

    fn remainder(&self) -> &'a str {
        &self.input[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{Record, RecordClass, RecordKind, ZoneParser};

    #[test]
    fn parse_origin() {
        let input = "$ORIGIN hello.";
        let mut parser = ZoneParser::from_str(input);
        parser.parse_zone().unwrap();
        assert_eq!(parser.origin, Some("hello."));
    }

    #[test]
    fn parse_ttl() {
        let input = "$TTL 60";
        let mut parser = ZoneParser::from_str(input);
        parser.parse_zone().unwrap();
        assert_eq!(parser.ttl, Some(60));
    }

    #[test]
    fn parse_multi_dx() {
        let input = "
            $ORIGIN hello.
            $TTL 60
        ";
        let mut parser = ZoneParser::from_str(input);
        parser.parse_zone().unwrap();
        assert_eq!(parser.origin, Some("hello."));
        assert_eq!(parser.ttl, Some(60));
    }

    #[test]
    fn parse_multi_dx_reorder() {
        let input = "
            $TTL 60
            $ORIGIN hello.
        ";
        let mut parser = ZoneParser::from_str(input);
        parser.parse_zone().unwrap();
        assert_eq!(parser.origin, Some("hello."));
        assert_eq!(parser.ttl, Some(60));
    }

    #[test]
    fn parse_comment() {
        let input = "$TTL 60 ; this is a comment";
        let mut parser = ZoneParser::from_str(input);
        parser.parse_zone().unwrap();
        assert_eq!(parser.ttl, Some(60));
    }

    #[test]
    fn parse_record_unsupported_type() {
        let input = "example.com. 60 IN B";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone();
        assert!(zone.is_err());
    }

    #[test]
    fn parse_record_ttl_first() {
        let input = "example.com. 60 IN A 0.0.0.0";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record {
                name: "example.com.".to_string(),
                kind: RecordKind::A("0.0.0.0".parse().unwrap()),
                class: RecordClass::In,
                ttl: 60
            }
        );
    }

    #[test]
    fn parse_record_ttl_first_class_missing() {
        let input = "example.com. 60 A 0.0.0.0";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record {
                name: "example.com.".to_string(),
                kind: RecordKind::A("0.0.0.0".parse().unwrap()),
                class: RecordClass::In,
                ttl: 60
            }
        );
    }

    #[test]
    fn parse_record_class_first() {
        let input = "example.com. IN 60 A 0.0.0.0";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record {
                name: "example.com.".to_string(),
                kind: RecordKind::A("0.0.0.0".parse().unwrap()),
                class: RecordClass::In,
                ttl: 60
            }
        );
    }

    #[test]
    fn parse_record_class_first_ttl_missing() {
        let input = "example.com. IN A 0.0.0.0";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record {
                name: "example.com.".to_string(),
                kind: RecordKind::A("0.0.0.0".parse().unwrap()),
                class: RecordClass::In,
                ttl: 60
            }
        );
    }

    #[test]
    fn parse_record_ttl_class_both_missing() {
        let input = "example.com. A 0.0.0.0";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record {
                name: "example.com.".to_string(),
                kind: RecordKind::A("0.0.0.0".parse().unwrap()),
                class: RecordClass::In,
                ttl: 60
            }
        );
    }

    #[test]
    fn parse_a_record() {
        let input = "example.com. 60 IN A 0.0.0.0";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record::new(
                "example.com.".into(),
                RecordClass::In,
                60,
                RecordKind::A(Ipv4Addr::new(0, 0, 0, 0)),
            )
        );
    }

    #[test]
    fn parse_aaaa_record() {
        let input = "example.com. 60 IN AAAA 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record::new(
                "example.com.".into(),
                RecordClass::In,
                60,
                RecordKind::Aaaa("2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap()),
            )
        );
    }

    #[test]
    fn parse_mx_record() {
        let input = "example.com. 60 IN MX 10 mail.example.com.";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record::new(
                "example.com.".into(),
                RecordClass::In,
                60,
                RecordKind::Mx(10, "mail.example.com.".into()),
            )
        );
    }

    #[test]
    fn parse_cname_record() {
        let input = "example.com. 60 IN CNAME example.org.";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record::new(
                "example.com.".into(),
                RecordClass::In,
                60,
                RecordKind::Cname("example.org.".into()),
            )
        );
    }

    #[test]
    fn parse_txt_record() {
        let input = "example.com. 60 IN TXT hello";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record::new(
                "example.com.".into(),
                RecordClass::In,
                60,
                RecordKind::Txt("hello".into()),
            )
        );
    }

    #[test]
    fn parse_ns_record() {
        let input = "example.com. 60 IN NS ns.example.com.";
        let mut parser = ZoneParser::from_str(input);
        let zone = parser.parse_zone().unwrap();
        assert_eq!(
            zone.records[0],
            Record::new(
                "example.com.".into(),
                RecordClass::In,
                60,
                RecordKind::Ns("ns.example.com.".into()),
            )
        );
    }
}
