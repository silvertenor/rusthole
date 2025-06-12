use std::fmt;

#[derive(Debug)]
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

    pub fn set_header(&mut self, header: Header) {
        self.header = Some(header);
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
    Question(Question),
    // Answer(Answer),
    Authority,
    Additional,
}

impl fmt::Display for ParsedSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsedSection::Header(h) => write!(f, "Header:\n{}", h),
            ParsedSection::Question(q) => write!(f, "Question section"),
            // ParsedSection::Answer(ans) => write!(f, "Answer section"),
            ParsedSection::Authority => write!(f, "Authority section"),
            ParsedSection::Additional => write!(f, "Additional section"),
        }
    }
}

#[derive(Debug)]
struct Record {
    preamble: Preamble,
    ip: [u8; 4],
}

#[derive(Debug)]
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
    pub start_index: usize,
    pub end_index: usize,
}

impl Question {
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
        let name = query;
        let qtype = u16::from(message_buf[bp]) << 8 | message_buf[bp + 1] as u16;
        let class = u16::from(message_buf[bp + 2]) << 8 | message_buf[bp + 3] as u16;
        dns_packet.byte_pointer += 3;
        ParsedSection::Question(Question {
            name,
            qtype,
            class,
            start_index,
            end_index,
        })
    }
}

pub struct Answer {
    name: Vec<u8>,
    atype: u16,
    class: u16,
    ttl: u32,
    len: u16,
}

// impl Answer {
//     pub fn new() -> ParsedSection {
//         ParsedSection::Answer(Answer {
//             name: Vec::new(),
//             atype: 0,
//             class: 0,
//             ttl: 0,
//             len: 0,
//         })
//     }

//     // ParsedSection::Answer(Answer {
//     //         name: buf.get(q.start_index..q.end_index).unwrap().to_vec(),
//     //         atype: q.qtype,
//     //         class: q.class,
//     //         ttl: 0,
//     //         len: 0,
//     //     })
// }
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
