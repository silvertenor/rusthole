use std::fmt;

pub struct DnsPacket {
    header: Header,
    question: Question,
    answer: Record,
    authority: Record,
    additional: Record,
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
    Question,
    Answer,
    Authority,
    Additional,
}

impl fmt::Display for ParsedSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsedSection::Header(h) => write!(f, "Header:\n{}", h),
            ParsedSection::Question => write!(f, "Question section"),
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
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl Header {
    pub fn new(buf: &Vec<u8>) -> ParsedSection {
        ParsedSection::Header(Header {
            id: u16::from(buf[0]) << 8 | buf[1] as u16,
            qr: buf[2] >> 7 & 1 != 0,
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

    pub fn display(&self) -> () {
        println!("{:?}", self);
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
            self.qr,
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
pub struct Question {
    name: Vec<u8>,
    qtype: [u8; 2],
    class: [u8; 2],
}
