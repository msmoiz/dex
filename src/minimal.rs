use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use dex::{Name, Record};
use serde::Serialize;

/// A minimal representation of a record.
///
/// It only contains the values for the record.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
#[serde(untagged)]
pub enum MinimalRecord {
    /// IPv4 address record.
    A { addr: Ipv4Addr },
    /// Name server record.
    Ns { host: Name },
    /// Mail destination record.
    Md { host: Name },
    /// Mail forwarded record.
    Mf { host: Name },
    /// Canonical name record.
    Cname { host: Name },
    /// Statement of authority record.
    Soa {
        origin: Name,
        mailbox: Name,
        version: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// Mailbox domain record.
    Mb { host: Name },
    /// Mail group record.
    Mg { host: Name },
    /// Mail rename record.
    Mr { host: Name },
    /// Null record.
    Null { data: Vec<u8> },
    /// Well known service record.
    Wks {
        addr: Ipv4Addr,
        protocol: u8,
        data: Vec<u8>,
    },
    /// Domain name pointer record.
    Ptr { host: Name },
    /// Host information record.
    Hinfo { cpu: String, os: String },
    /// Mailbox information record.
    Minfo { r_mailbox: Name, e_mailbox: Name },
    /// Mail exchange record.
    Mx { priority: u16, host: Name },
    /// Text record.
    Txt { content: String },
    /// IPv6 address record.
    Aaaa { addr: Ipv6Addr },
    /// EDNS options record.
    Opt {
        max_response_size: u16,
        extended_rcode: u8,
        version: u8,
        dnssec_ok: bool,
        data: Vec<u8>,
    },
}

impl From<Record> for MinimalRecord {
    fn from(value: Record) -> Self {
        match value {
            Record::A { addr, .. } => MinimalRecord::A { addr },
            Record::Ns { host, .. } => MinimalRecord::Ns { host },
            Record::Md { host, .. } => MinimalRecord::Md { host },
            Record::Mf { host, .. } => MinimalRecord::Mf { host },
            Record::Cname { host, .. } => MinimalRecord::Cname { host },
            Record::Soa {
                origin,
                mailbox,
                version,
                refresh,
                retry,
                expire,
                minimum,
                ..
            } => MinimalRecord::Soa {
                origin,
                mailbox,
                version,
                refresh,
                retry,
                expire,
                minimum,
            },
            Record::Mb { host, .. } => MinimalRecord::Mb { host },
            Record::Mg { host, .. } => MinimalRecord::Mg { host },
            Record::Mr { host, .. } => MinimalRecord::Mr { host },
            Record::Null { data, .. } => MinimalRecord::Null { data },
            Record::Wks {
                addr,
                protocol,
                data,
                ..
            } => MinimalRecord::Wks {
                addr,
                protocol,
                data,
            },
            Record::Ptr { host, .. } => MinimalRecord::Ptr { host },
            Record::Hinfo { cpu, os, .. } => MinimalRecord::Hinfo { cpu, os },
            Record::Minfo {
                r_mailbox,
                e_mailbox,
                ..
            } => MinimalRecord::Minfo {
                r_mailbox,
                e_mailbox,
            },
            Record::Mx { priority, host, .. } => MinimalRecord::Mx { priority, host },
            Record::Txt { content, .. } => MinimalRecord::Txt { content },
            Record::Aaaa { addr, .. } => MinimalRecord::Aaaa { addr },
            Record::Opt {
                max_response_size,
                extended_rcode,
                version,
                dnssec_ok,
                data,
                ..
            } => MinimalRecord::Opt {
                max_response_size,
                extended_rcode,
                version,
                dnssec_ok,
                data,
            },
        }
    }
}

impl Display for MinimalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MinimalRecord::A { addr, .. } => write!(f, "{addr}"),
            MinimalRecord::Ns { host, .. } => write!(f, "{host}"),
            MinimalRecord::Md { host, .. } => write!(f, "{host}"),
            MinimalRecord::Mf { host, .. } => write!(f, "{host}"),
            MinimalRecord::Cname { host, .. } => write!(f, "{host}"),
            MinimalRecord::Soa {
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
                "{origin} {mailbox} {version} {refresh} {retry} {expire} {minimum}"
            ),
            MinimalRecord::Mb { host, .. } => write!(f, "{host}"),
            MinimalRecord::Mg { host, .. } => write!(f, "{host}"),
            MinimalRecord::Mr { host, .. } => write!(f, "{host}"),
            MinimalRecord::Null { data, .. } => write!(f, "{data:x?}"),
            MinimalRecord::Wks {
                addr,
                protocol,
                data,
                ..
            } => write!(f, "{addr} {protocol} {data:x?}"),
            MinimalRecord::Ptr { host, .. } => write!(f, "{host}"),
            MinimalRecord::Hinfo { cpu, os, .. } => write!(f, "{cpu} {os}"),
            MinimalRecord::Minfo {
                r_mailbox,
                e_mailbox,
                ..
            } => write!(f, "{r_mailbox} {e_mailbox}"),
            MinimalRecord::Mx { priority, host, .. } => write!(f, "{priority} {host}"),
            MinimalRecord::Txt { content, .. } => write!(f, "{content}"),
            MinimalRecord::Aaaa { addr, .. } => write!(f, "{addr}"),
            MinimalRecord::Opt { data, .. } => write!(f, "{data:x?}"),
        }
    }
}
