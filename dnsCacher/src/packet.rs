use std::fmt;

pub struct DnsPacket {
    header: Option<Header>,
    question: Option<Question>,
    answer: Option<Record>,
    authority: Option<Record>,
    additional: Option<Record>,
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
}

pub enum Section {
    Header,
    Question,
    Answer,
    Authority,
    Additional,
}

#[derive(Debug)]
pub enum ParsedSection {
    Header(Header),
    Question(Question),
    Answer,
    Authority,
    Additional,
}

impl fmt::Display for ParsedSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsedSection::Header(h) => write!(f, "Header:\n{}", h),
            ParsedSection::Question(q) => write!(f, "Question section"),
            ParsedSection::Answer => write!(f, "Answer section"),
            ParsedSection::Authority => write!(f, "Authority section"),
            ParsedSection::Additional => write!(f, "Additional section"),
        }
    }
}

struct Record {
    preamble: Preamble,
    ip: [u8; 4],
}

pub struct Preamble {
    name: Vec<u8>,
    rtype: [u8; 2],
    class: [u8; 2],
    ttl: [usize; 4],
    len: [u8; 2],
}

#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub response: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    pub qdcount: u16,
    ancount: u16,
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
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
}

impl Question {
    pub fn new(mut message_buf: Vec<u8>, dns_packet: &mut DnsPacket) -> ParsedSection {
        let start_index: usize = dns_packet.byte_pointer;
        message_buf = message_buf.get(start_index..).unwrap().to_vec();
        let mut query = String::new();
        'outer: loop {
            let mut i: u8 = 1;
            for j in i..=message_buf[0] {
                query.push(message_buf[j as usize].to_ascii_lowercase() as char);
                i = j + 1;
                // Update byte pointer:
                dns_packet.byte_pointer += 1;
            }
            message_buf = message_buf.get((i as usize)..).unwrap().to_vec();
            if message_buf[0] == 0 {
                dns_packet.byte_pointer += 1;
                break 'outer;
            } else {
                dns_packet.byte_pointer += 1;
                query.push('.');
            }
        }
        println!("{:?}", dns_packet.byte_pointer);
        // println!("{:?}", )
        let name = query;
        let type_index = (1) as usize;
        let qtype = u16::from(message_buf[type_index]) << 8 | message_buf[type_index + 1] as u16;
        let class_index = type_index + 2 as usize;
        let class = u16::from(message_buf[class_index]) << 8 | message_buf[class_index + 1] as u16;
        ParsedSection::Question(Question { name, qtype, class })
    }
    // pub fn parse_question(&mut self, mut message_buf: Vec<u8>) {
    //     let mut query = String::new();
    //     'outer: loop {
    //         let mut i: u8 = 1;
    //         for j in i..=message_buf[0] {
    //             query.push(message_buf[j as usize].to_ascii_lowercase() as char);
    //             i = j + 1;
    //         }
    //         message_buf = message_buf.get((i as usize)..).unwrap().to_vec();
    //         if message_buf[0] == 0 {
    //             break 'outer;
    //         } else {
    //             query.push('.');
    //         }
    //     }
    //     // end of query relative to 12-byte offset for the QUERY section (however the message_buf is altered here so it will be relative to last change)
    //     self.eof = message_buf.iter().position(|&i| i == 0).unwrap() as u16;
    //     self.name = query;
    //     let type_index = (self.eof + 1) as usize;
    //     self.qtype = u16::from(message_buf[type_index]) << 8 | message_buf[type_index + 1] as u16;
    //     let class_index = type_index + 2 as usize;
    //     self.class = u16::from(message_buf[class_index]) << 8 | message_buf[class_index + 1] as u16;
    // }
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
        let h = Header::new(&buf);
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
