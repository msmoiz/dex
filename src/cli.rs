mod logger;
mod minimal;

use std::{fs, process::ExitCode, str::FromStr};

use anyhow::{bail, Context};
use clap::{ArgAction, Parser, ValueEnum};
use dex::{
    Message, Name, Question, QuestionClass, QuestionType, Record, ResponseCode, TcpTransport,
    UdpTransport,
};
use log::{error, warn};
use logger::init_logger;
use minimal::MinimalRecord;

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
    args: Vec<String>,
    /// Use UDP to send the request. (default: UDP with TCP fallback)
    #[arg(long, default_value_t = false)]
    udp: bool,
    /// Use TCP to send the request. (default: UDP with TCP fallback)
    #[arg(long, default_value_t = false)]
    tcp: bool,
    /// Disable EDNS(0) for the request. (default: EDNS enabled)
    #[arg(long, action=ArgAction::SetFalse)]
    no_edns: bool,
    /// The amount of information to include in the output. (default: standard)
    #[arg(long)]
    detail: Detail,
}

/// The amount of information to include in the output.
#[derive(Debug, Clone, ValueEnum)]
enum Detail {
    /// Only show values for answer records.
    Minimal,
    /// Show all information for answer records.
    Standard,
    /// Show the full response.
    Full,
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

impl TryFrom<Vec<String>> for Args {
    type Error = anyhow::Error;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let mut args = Self::default();
        for arg in value {
            if let Some(nameserver) = arg.strip_prefix("@") {
                match args.nameserver.as_ref() {
                    Some(_) => bail!("nameserver specified more than once"),
                    None => args.nameserver = Some(nameserver.to_owned()),
                }
                continue;
            }

            if let Ok(q_type) = QuestionType::from_str(&arg) {
                match args.q_type.as_ref() {
                    Some(_) => bail!("type specified more than once"),
                    None => args.q_type = Some(q_type),
                }
                continue;
            }

            if let Ok(q_class) = QuestionClass::from_str(&arg) {
                match args.q_class.as_ref() {
                    Some(_) => bail!("class specified more than once"),
                    None => args.q_class = Some(q_class),
                }
                continue;
            }

            bail!("unrecognized argument: {arg}");
        }
        Ok(args)
    }
}

fn main() -> ExitCode {
    init_logger();

    let Cli {
        domain,
        udp,
        tcp,
        args,
        no_edns: edns,
        detail,
    } = Cli::parse();

    let Args {
        q_type,
        q_class,
        nameserver,
    } = match Args::try_from(args).context("failed to parse freeform arguments") {
        Ok(args) => args,
        Err(e) => {
            error!("{e:?}");
            return ExitCode::from(1);
        }
    };

    if let Ok(true) = Hosts::contains(&domain.to_string()) {
        warn!("{} is present in hosts file", domain);
    }

    let mut request = Message::new();
    request.header.recursion_desired = true;

    request.header.question_count = 1;
    request.questions = vec![Question {
        name: domain,
        q_type: q_type.unwrap_or(QuestionType::A),
        q_class: q_class.unwrap_or(QuestionClass::In),
    }];

    let max_response_size = if edns { 4096 } else { 512 };

    if edns {
        request.additional_records = vec![Record::Opt {
            name: Name::from_str(".").unwrap(),
            max_response_size,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            data: vec![],
        }];
    }

    let nameserver = nameserver.unwrap_or(find_default_nameserver());

    let response = {
        if tcp {
            TcpTransport::new(nameserver).send(request)
        } else if udp {
            UdpTransport::new(nameserver, max_response_size).send(request)
        } else {
            let response =
                UdpTransport::new(nameserver.clone(), max_response_size).send(request.clone());
            if response.header.is_truncated {
                TcpTransport::new(nameserver).send(request)
            } else {
                response
            }
        }
    };

    match response.header.resp_code {
        ResponseCode::Success => match detail {
            Detail::Minimal => {
                for record in response.answer_records {
                    println!("{}", MinimalRecord::from(record))
                }
            }
            Detail::Standard => {
                for record in &response.answer_records {
                    println!("{record}")
                }
            }
            Detail::Full => {
                println!("{}", response.header);

                for question in &response.questions {
                    println!(
                        "{} {} {} ?",
                        question.name, question.q_type, question.q_class
                    );
                }

                for record in &response.answer_records {
                    println!("{record}")
                }

                for record in &response.authority_records {
                    println!("{record} !")
                }

                for record in &response.additional_records {
                    println!("{record} +")
                }
            }
        },
        c @ _ => {
            eprintln!("status: {c}");
            return ExitCode::from(1);
        }
    };

    ExitCode::default()
}

/// Represents the hosts file found on most operating systems.
struct Hosts;

impl Hosts {
    /// Returns true if the hosts file contains the given host.
    fn contains(host: &str) -> anyhow::Result<bool> {
        #[cfg(unix)]
        let path = "/etc/hosts";

        #[cfg(windows)]
        let path = "C:/Windows/System32/drivers/etc/hosts";

        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to load hosts file at {path}"))?;

        Ok(Self::contains_inner(&content, host))
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
#[cfg(unix)]
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

/// Finds the default nameserver for this operating system.
#[cfg(windows)]
fn find_default_nameserver() -> String {
    use std::{
        io,
        net::{IpAddr, UdpSocket},
    };

    // Get the IP of the network adapter that is used to access the internet
    // https://stackoverflow.com/questions/24661022/getting-ip-adress-associated-to-real-hardware-ethernet-controller-in-windows-c
    fn get_ipv4() -> io::Result<IpAddr> {
        let s = UdpSocket::bind("0.0.0.0:0")?;
        s.connect("8.8.8.8:53")?;
        let addr = s.local_addr()?;
        Ok(addr.ip())
    }

    let ip = get_ipv4().ok();

    let adapters = ipconfig::get_adapters().unwrap();
    let active_adapters = adapters.iter().filter(|a| {
        a.oper_status() == ipconfig::OperStatus::IfOperStatusUp && !a.gateways().is_empty()
    });

    if let Some(dns_server) = active_adapters
        .clone()
        .find(|a| ip.map(|ip| a.ip_addresses().contains(&ip)).unwrap_or(false))
        .map(|a| a.dns_servers().first())
        .flatten()
    {
        let nameserver = dns_server.to_string();
        return nameserver;
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
