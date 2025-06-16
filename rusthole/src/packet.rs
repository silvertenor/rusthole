use std::fmt;

#[derive(Debug)]
pub struct DnsPacket {
    header: Option<Vec<u8>>,
    question: Option<Vec<u8>>,
    answer: Option<Vec<u8>>,
    pub authority: Option<Vec<u8>>,
    pub additional: Option<Vec<u8>>,
    pub bytes: Vec<u8>,
    pub byte_pointer: usize,
}
impl DnsPacket {
    pub fn new(buf: &Vec<u8>) -> DnsPacket {
        DnsPacket {
            header: None,
            question: None,
            answer: None,
            authority: None,
            additional: None,
            bytes: buf.to_vec(),
            byte_pointer: 0,
        }
    }
    pub fn build_packet(&mut self) -> Vec<u8> {
        let mut response_buf: Vec<u8> = Vec::with_capacity(512);
        if let Some(header) = &self.get_header() {
            response_buf.extend_from_slice(&header);
        }
        if let Some(query) = &self.get_query() {
            // let question_bytes = question.response_buf.extend_from_slice(&buf.get);
            response_buf.extend_from_slice(&query);
        }
        if let Some(answer) = &self.get_answer() {
            response_buf.extend_from_slice(&answer);
        }
        if Option::is_some(&self.authority) {
            todo!();
        }
        if Option::is_some(&self.additional) {
            todo!();
        }
        response_buf
    }
    pub fn set_header(&mut self, header: Header) {
        let mut packet_header: Vec<u8> = Vec::with_capacity(12);
        packet_header.extend_from_slice(&header.id.to_be_bytes());
        packet_header.extend_from_slice(&[(header.response as u8) << 7
            | (header.opcode as u8) << 3
            | (header.aa as u8) << 2
            | (header.tc as u8) << 1
            | (header.rd as u8)]);
        packet_header.extend_from_slice(&[(header.ra as u8) << 7
            | (header.z as u8) << 4
            | (header.rcode as u8)]);
        packet_header.extend_from_slice(&header.qdcount.to_be_bytes());
        packet_header.extend_from_slice(&header.ancount.to_be_bytes());
        packet_header.extend_from_slice(&header.nscount.to_be_bytes());
        packet_header.extend_from_slice(&header.arcount.to_be_bytes());
        self.header = Some(packet_header);
    }

    pub fn get_header(&self) -> &Option<Vec<u8>> {
        &self.header
    }

    pub fn set_query(&mut self, q: &Query) {
        let mut packet_question: Vec<u8> = Vec::new();
        packet_question.extend_from_slice(&q.name_bytes);
        packet_question.extend_from_slice(&q.qtype.to_be_bytes());
        packet_question.extend_from_slice(&q.class.to_be_bytes());
        self.question = Some(packet_question);
    }

    pub fn get_query(&self) -> &Option<Vec<u8>> {
        &self.question
    }

    pub fn set_answer(&mut self, r: &Record) {
        let mut packet_record: Vec<u8> = Vec::new();
        packet_record.extend_from_slice(&r.preamble.name);
        packet_record.extend_from_slice(&r.preamble.rtype.to_be_bytes());
        packet_record.extend_from_slice(&r.preamble.class.to_be_bytes());
        packet_record.extend_from_slice(&r.preamble.ttl.to_be_bytes());
        packet_record.extend_from_slice(&r.preamble.len.to_be_bytes());
        packet_record.extend_from_slice(&r.ip);
        self.answer = Some(packet_record);
    }

    pub fn get_answer(&self) -> &Option<Vec<u8>> {
        &self.answer
    }
}

#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub response: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    pub rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    nscount: u16,
    arcount: u16,
}
impl Header {
    pub fn new(buf: &Vec<u8>, dns_packet: &mut DnsPacket) -> ParsedSection {
        // Increment byte pointer to 12 - the first byte after the header
        dns_packet.byte_pointer = 12;
        ParsedSection::Header(Header {
            id: u16::from(buf[0]) << 8 | buf[1] as u16,
            response: buf[2] >> 7 & 1 != 0,
            opcode: buf[2] >> 3 & 0x0F,
            aa: buf[2] >> 2 & 1 != 0,
            tc: buf[2] >> 1 & 1 != 0,
            rd: buf[2] & 1 != 0,
            ra: buf[3] >> 7 & 1 != 0,
            z: buf[3] >> 4 & 0x0F,
            rcode: buf[3] & 0xf,
            qdcount: u16::from(buf[4]) << 8 | buf[5] as u16,
            ancount: u16::from(buf[6]) << 8 | buf[7] as u16,
            nscount: u16::from(buf[8]) << 8 | buf[9] as u16,
            arcount: u16::from(buf[10]) << 8 | buf[11] as u16,
        })
    }
}
impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ID: {:?}
Response: {:?}
OPCODE: {:#06b}
Authoritative Answer: {:?}
Truncated Message: {:?}
Recursion Desired: {:?}
Recursion Available: {:?}
Z(Reserved): {:#05b}
RCODE: {:#06b}
Questions: {:?}
Answers: {:?}
Authority Count: {:?}
Additional Count {:?}",
            self.id,
            self.response,
            self.opcode,
            self.aa,
            self.tc,
            self.rd,
            self.ra,
            self.z,
            self.rcode,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )
    }
}

#[derive(Debug)]
pub struct Query {
    pub name_str: String,
    pub name_bytes: Vec<u8>,
    pub qtype: u16,
    pub class: u16,
    pub start_index: usize,
    pub end_index: usize,
}
impl Query {
    pub fn new(message_buf: Vec<u8>, dns_packet: &mut DnsPacket) -> ParsedSection {
        let start_index = dns_packet.byte_pointer as usize; // for struct
        let mut bp = dns_packet.byte_pointer; // to save space in arr indexing
        let mut query = String::new();
        // "Build" question string from label syntax in packet
        'outer: loop {
            let start_char_index = bp + 1;
            let end_char_index = start_char_index + message_buf[bp] as usize;
            bp = end_char_index;
            query.push_str(str::from_utf8(&message_buf[start_char_index..end_char_index]).unwrap());
            if message_buf[bp] == 0 {
                bp += 1;
                break 'outer;
            } else {
                query.push('.');
            }
        }
        let end_index = bp as usize; // for struct
        dns_packet.byte_pointer = bp;
        let name_str = query;
        let name_bytes = message_buf.get(start_index..end_index).unwrap().to_vec();
        let qtype = u16::from(message_buf[bp]) << 8 | message_buf[bp + 1] as u16;
        let class = u16::from(message_buf[bp + 2]) << 8 | message_buf[bp + 3] as u16;
        dns_packet.byte_pointer += 3;
        ParsedSection::Question(Query {
            name_str,
            name_bytes,
            qtype,
            class,
            start_index,
            end_index,
        })
    }
}

#[derive(Debug)]
pub struct Preamble {
    name: Vec<u8>,
    rtype: u16,
    class: u16,
    ttl: u32,
    len: u16,
}

#[derive(Debug)]
pub struct Record {
    preamble: Preamble,
    ip: [u8; 4],
}
impl Record {
    pub fn new(q: &Query) -> Record {
        // Get record:
        let first: u8 = 127;
        let second: u8 = 0;
        let third: u8 = 0;
        let fourth: u8 = 1;
        // if dns_records.contains_key(&q.name_str) {
        //     let ip_addr = &dns_records
        //         .get(&q.name_str)
        //         .unwrap()
        //         .get(0)
        //         .unwrap()
        //         .to_string();
        //     let split: Vec<&str> = ip_addr.split('.').collect();
        //     first = split.get(0).unwrap().parse().unwrap();
        //     second = split.get(1).unwrap().parse().unwrap();
        //     third = split.get(2).unwrap().parse().unwrap();
        //     fourth = split.get(3).unwrap().parse().unwrap();
        // }
        let preamble = Preamble {
            name: q.name_bytes.to_vec(),
            rtype: q.qtype,
            class: q.class,
            ttl: 600,
            len: 4,
        };
        Record {
            preamble,
            ip: [first, second, third, fourth],
        }
    }
}
pub enum Section {
    Header,
    Question,
    // Answer,
    Authority,
    Additional,
}

#[derive(Debug)]
pub enum ParsedSection {
    Header(Header),
    Question(Query),
    Authority,
    Additional,
}
impl fmt::Display for ParsedSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsedSection::Header(h) => write!(f, "Header:\n{}", h),
            ParsedSection::Question(q) => write!(f, "Queery:\n{:?}", q),
            ParsedSection::Authority => write!(f, "Authority section"),
            ParsedSection::Additional => write!(f, "Additional section"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header() {
        let mut buf: Vec<u8> = Vec::from([0; 512]);
        for i in 0..12 {
            buf[i] = 128 - i as u8;
        }
        let mut dns_packet = DnsPacket::new(&buf);
        let h = Header::new(&buf, &mut dns_packet);
        if let ParsedSection::Header(header) = h {
            assert_eq!(header.id, 32895);
            assert_eq!(header.response, false);
            assert_eq!(header.opcode, 0b1111);
            assert_eq!(header.aa, true);
            assert_eq!(header.tc, true);
            assert_eq!(header.rd, false);
            assert_eq!(header.ra, false);
            assert_eq!(header.z, 0b111);
            assert_eq!(header.rcode, 0b1101);
            assert_eq!(header.qdcount, 31867);
            assert_eq!(header.ancount, 31353);
            assert_eq!(header.nscount, 30839);
            assert_eq!(header.arcount, 30325);
        } else {
            println!("Not a header!");
        }
    }
}
