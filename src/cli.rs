use clap::Parser;
use rolodex::{Bytes, Message, Name, Question, QuestionClass, QuestionType, ResponseCode};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// The domain to find records for.
    domain: String,
}

fn main() {
    let cli = Cli::parse();

    let mut query = Message::new();
    query.header.recursion_desired = true;
    query.header.question_count = 1;
    query.questions = vec![Question {
        name: Name::from_str(&cli.domain),
        q_type: QuestionType::A,
        q_class: QuestionClass::In,
    }];

    let socket = std::net::UdpSocket::bind("0.0.0.0:5380").unwrap();

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
