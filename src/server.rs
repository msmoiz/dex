use std::fs;

use dex::{Bytes, Message, OperationCode, QuestionType, Record, ResponseCode, Zone};

fn main() {
    Server::start();
}

/// A DNS server.
struct Server {
    zone: Zone,
}

impl Server {
    /// Starts a new DNS server.
    fn start() {
        let zone_file = "zone.toml";
        println!("loading zone data from {zone_file}");
        let zone_data = fs::read_to_string(zone_file).unwrap();
        let zone = Zone::from_toml(&zone_data).unwrap();
        let server = Self { zone };

        println!("listening on port 5380");
        let socket = std::net::UdpSocket::bind("0.0.0.0:5380").unwrap();
        loop {
            let mut query_buffer = [0; 512];
            let (_, addr) = socket.recv_from(&mut query_buffer).unwrap();
            println!("received query from {addr}");

            let mut query_bytes = Bytes::from_buf(&query_buffer);
            let query = Message::from_bytes(&mut query_bytes);

            let response = server.serve(query);
            println!("response: {:?}", response.header.resp_code);

            let mut response_bytes = Bytes::new();
            response.to_bytes(&mut response_bytes);
            socket.send_to(response_bytes.used(), addr).unwrap();

            println!("returned response to sender");
        }
    }

    /// Serves a DNS query.
    ///
    /// Returns a DNS response.
    fn serve(&self, query: Message) -> Message {
        let mut response = query;
        response.header.is_response = true;

        let question = &response.questions[0];
        println!("question: {} {:?}", question.name, question.q_type);

        if !matches!(response.header.op_code, OperationCode::Query) {
            response.header.resp_code = ResponseCode::NotImplemented;
            println!("response: {:?}", response.header.resp_code);
            return response;
        }

        let mut wildcard_answers: Option<Vec<&Record>> = None;

        for qname in question.name.ancestors() {
            let name_records = self.zone.find_with_name(&qname);

            // if there are records at this level, discard wildcard answers
            if !name_records.is_empty() {
                wildcard_answers = None;
            }

            // leaf
            if qname == question.name {
                // check for cname
                if let Some(cname_record) = name_records
                    .iter()
                    .find(|r| matches!(r, Record::Cname { .. }))
                {
                    response.header.is_authority = true;
                    response.header.resp_code = ResponseCode::Success;
                    response.header.answer_count = 1;
                    response.answer_records.push((*cname_record).clone());
                    return response;
                }

                // check for exact matches
                let matched_records: Vec<_> = name_records
                    .iter()
                    .filter(|r| {
                        r.code() == question.q_type.code()
                            || matches!(question.q_type, QuestionType::ALL)
                    })
                    .collect();

                if !matched_records.is_empty() {
                    response.header.is_authority = true;
                    response.header.resp_code = ResponseCode::Success;
                    response.header.answer_count = matched_records.len() as u16;
                    for record in matched_records {
                        response.answer_records.push((*record).clone());
                    }
                    return response;
                }
            }

            // leaf or ancestor: check for delegation
            let delegation_records: Vec<_> = name_records
                .iter()
                .filter(|r| matches!(r, Record::Ns { .. }))
                .collect();

            if !delegation_records.is_empty() {
                response.header.is_authority = false;
                response.header.resp_code = ResponseCode::Success;
                response.header.authority_count = delegation_records.len() as u16;
                for record in delegation_records {
                    response.authority_records.push((*record).clone());
                }
                return response;
            }

            // do not consider wildcards for root
            if qname.is_root() {
                continue;
            }

            // if there are records at this level, do not look for wildcard answers
            if !name_records.is_empty() {
                continue;
            }

            // leaf or ancestor: check for wildcards
            let wildcard_records: Vec<_> = self
                .zone
                .find_with_name(&qname.to_wildcard())
                .into_iter()
                .filter(|r| r.code() == question.q_type.code())
                .collect();

            // if there are matching wildcard records, hang on to them
            if !wildcard_records.is_empty() {
                wildcard_answers = Some(wildcard_records);
            }
        }

        // there are matching wildcard records and no records for names in
        // between the wildcard and the question name
        if let Some(records) = wildcard_answers {
            response.header.is_authority = true;
            response.header.resp_code = ResponseCode::Success;
            response.header.answer_count = records.len() as u16;
            for record in records {
                response
                    .answer_records
                    .push(record.with_name(question.name.clone()));
            }
            return response;
        }

        response.header.resp_code = ResponseCode::NameError;
        response
    }
}
