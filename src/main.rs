use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
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

/// A subset of the DNS namespace.
///
/// This usually represents a single domain.
struct Zone {}

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
}

impl<'a> ZoneParser<'a> {
    fn from_str(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            origin: None,
            owner: None,
            ttl: None,
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
        }

        Ok(Zone {})
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
                'a'..='z' | 'A'..='Z' | '.' => len += char.len_utf8(),
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

    fn remainder(&self) -> &'a str {
        &self.input[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use crate::ZoneParser;

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
}
