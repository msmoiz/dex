use std::{fs, str::FromStr};

use clap::Parser;
use rolodex::{Bytes, Message, Name, Question, QuestionClass, QuestionType, ResponseCode};

#[derive(Parser, Debug)]
#[command(version, about, max_term_width = 80)]
struct Cli {
    /// The domain to find records for.
    ///
    /// If the domain is relative, it will be converted to a fully qualified
    /// domain name. For example, "example.com" will be converted to
    /// "example.com.".
    domain: String,
    /// Freeform arguments to modify the request.
    ///
    /// The following arguments are supported:
    ///
    /// [type]: The type of record to search for, specified using the alphabetic
    /// code for the record (e.g., A, MX, NS, ...). (default: A)
    ///
    /// [nameserver]: The nameserver to send the request to, specified with an @
    /// symbol in front of the name (e.g., @8.8.8.8). The nameserver may include
    /// a port number (e.g., @8.8.8.8:53), and the host may be specified using a
    /// hostname or an IP address. (default: system default nameserver)
    ///
    /// Each type of argument may be specified only once and may be specified in
    /// any order.
    args: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    let domain = to_fqdn(cli.domain);

    if Hosts::contains(&domain) {
        eprintln!("warning: {} is present in hosts file", domain);
    }

    let (q_type, nameserver) = {
        let mut q_type: Option<QuestionType> = None;
        let mut nameserver: Option<String> = None;
        for arg in cli.args {
            match arg.strip_prefix("@") {
                Some(ns) => nameserver = Some(ns.to_owned()),
                None => q_type = Some(QuestionType::from_str(&arg).unwrap()),
            }
        }
        (q_type, nameserver)
    };

    let mut query = Message::new();
    query.header.recursion_desired = true;
    query.header.question_count = 1;
    query.questions = vec![Question {
        name: Name::from_str(&domain),
        q_type: q_type.unwrap_or(QuestionType::A),
        q_class: QuestionClass::In,
    }];

    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();

    let mut query_bytes = Bytes::new();
    query.to_bytes(&mut query_bytes);

    let nameserver = nameserver.unwrap_or(find_default_nameserver());

    if nameserver.contains(":") {
        socket.send_to(query_bytes.used(), nameserver).unwrap();
    } else {
        socket
            .send_to(query_bytes.used(), (nameserver, 53))
            .unwrap();
    }

    let mut response_buf = [0; 512];
    let (_, _) = socket.recv_from(&mut response_buf).unwrap();
    let mut response_bytes = Bytes::from_buf(response_buf);
    let response = Message::from_bytes(&mut response_bytes);

    match response.header.resp_code {
        ResponseCode::Success => {
            for record in &response.answer_records {
                println!("{record}")
            }
        }
        _ => {
            // no op
        }
    };
}

/// Converts a domain name to a fully qualified domain name, if it is not one
/// already. In practice, this means adding a root label to the end of the
/// domain if it is not present.
fn to_fqdn(mut domain: String) -> String {
    if !domain.ends_with(".") {
        domain.push('.')
    }
    domain
}

/// Represents the hosts file found on most operating systems.
struct Hosts;

impl Hosts {
    /// Returns true if the hosts file contains the given host.
    fn contains(host: &str) -> bool {
        let content = fs::read_to_string("/etc/hosts").unwrap();
        Self::contains_inner(&content, host)
    }

    fn contains_inner(input: &str, host: &str) -> bool {
        for line in input.lines() {
            if line.starts_with("#") || line.trim().is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            while let Some(in_host) = parts.next() {
                if in_host == host || to_fqdn(in_host.to_owned()) == host {
                    return true;
                }
            }
        }
        false
    }
}

/// Finds the default nameserver for this operating system.
fn find_default_nameserver() -> String {
    let config = fs::read_to_string("/etc/resolv.conf").unwrap();
    for line in config.lines() {
        let mut parts = line.split_whitespace();
        if matches!(parts.next(), Some("nameserver")) {
            match parts.next() {
                Some(addr) => return addr.to_owned(),
                None => panic!("resolver config is malformed"),
            }
        }
    }
    panic!("failed to locate default nameserver")
}

#[cfg(test)]
mod tests {
    use crate::Hosts;

    #[test]
    fn hosts_contains() {
        let input = "127.0.0.1 localhost";
        let contains = Hosts::contains_inner(input, "localhost");
        assert!(contains);
    }
}
