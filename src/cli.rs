use std::fs;

use clap::Parser;
use rolodex::{Bytes, Message, Name, Question, QuestionClass, ResponseCode};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// The domain to find records for.
    ///
    /// If the domain is relative, it will be converted to an FQDN.
    /// Example: example.com -> example.com.
    domain: String,
    /// The type of record to search for.
    #[clap(value_name="TYPE", default_value_t=String::from("A"))]
    record_type: String,
}

fn main() {
    let cli = Cli::parse();

    let domain = to_fqdn(cli.domain);

    if Hosts::contains(&domain) {
        eprintln!("warning: {} is present in hosts file", domain);
    }

    let mut query = Message::new();
    query.header.recursion_desired = true;
    query.header.question_count = 1;
    query.questions = vec![Question {
        name: Name::from_str(&domain),
        q_type: cli.record_type.parse().unwrap(),
        q_class: QuestionClass::In,
    }];

    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();

    let mut query_bytes = Bytes::new();
    query.to_bytes(&mut query_bytes);
    socket.send_to(query_bytes.used(), "8.8.8.8:53").unwrap();

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
