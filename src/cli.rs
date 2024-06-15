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
    #[clap(default_value_t=String::from("A"))]
    record_type: String,
}

fn main() {
    let cli = Cli::parse();

    let mut query = Message::new();
    query.header.recursion_desired = true;
    query.header.question_count = 1;
    query.questions = vec![Question {
        name: Name::from_str(&to_fqdn(cli.domain)),
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
