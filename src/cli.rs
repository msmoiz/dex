use std::{convert::Infallible, fs, str::FromStr};

use clap::Parser;
use dex::{Bytes, Message, Name, Question, QuestionClass, QuestionType, ResponseCode};

#[derive(Parser, Debug)]
#[command(version, about, max_term_width = 80)]
struct Cli {
    /// The domain to find records for.
    ///
    /// If the domain is relative, it will be converted to a fully qualified
    /// domain name. For example, "example.com" will be converted to
    /// "example.com.".
    domain: Name,
    /// Freeform arguments to modify the request.
    ///
    /// The following arguments are supported:
    ///
    /// [type]: The type of record to search for, specified using the alphabetic
    /// code for the record (e.g., A, MX, NS, ...). (default: A)
    ///
    /// [class]: The class of the request, specified using the alphabetic code
    /// for the class (e.g., IN, HS, ...). (default: IN)
    ///
    /// [nameserver]: The nameserver to send the request to, specified with an @
    /// symbol in front of the name (e.g., @8.8.8.8). The nameserver may include
    /// a port number (e.g., @8.8.8.8:53), and the host may be specified using a
    /// hostname or an IP address. (default: system default nameserver)
    ///
    /// Each type of argument may be specified only once and may be specified in
    /// any order.
    #[clap(num_args = 0..)]
    args: Args,
}

/// Freeform arguments to modify the request.
#[derive(Debug, Clone, Default)]
struct Args {
    /// The type of record to search for.
    q_type: Option<QuestionType>,
    /// The class of the request.
    q_class: Option<QuestionClass>,
    /// The nameserver to send the request to.
    nameserver: Option<String>,
}

impl FromStr for Args {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut args = Self::default();
        for arg in s.split_whitespace() {
            if let Some(nameserver) = arg.strip_prefix("@") {
                match args.nameserver.as_ref() {
                    Some(_) => panic!("nameserver specified more than once"),
                    None => args.nameserver = Some(nameserver.to_owned()),
                }
                continue;
            }

            if let Ok(q_type) = QuestionType::from_str(&arg) {
                match args.q_type.as_ref() {
                    Some(_) => panic!("type specified more than once"),
                    None => args.q_type = Some(q_type),
                }
                continue;
            }

            if let Ok(q_class) = QuestionClass::from_str(&arg) {
                match args.q_class.as_ref() {
                    Some(_) => panic!("class specified more than once"),
                    None => args.q_class = Some(q_class),
                }
                continue;
            }

            panic!("unrecognized argument: {arg}");
        }
        Ok(args)
    }
}

fn main() {
    let Cli {
        domain,
        args: Args {
            q_type,
            q_class,
            nameserver,
        },
    } = Cli::parse();

    if Hosts::contains(&domain.to_string()) {
        eprintln!("warning: {} is present in hosts file", domain);
    }

    let mut query = Message::new();
    query.header.recursion_desired = true;
    query.header.question_count = 1;
    query.questions = vec![Question {
        name: domain,
        q_type: q_type.unwrap_or(QuestionType::A),
        q_class: q_class.unwrap_or(QuestionClass::In),
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
                if in_host == host || (in_host.to_owned() + ".") == host {
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
