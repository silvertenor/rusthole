use dns_lookup::lookup_host;
use std::io::Result;
use std::net::UdpSocket;
use std::{collections::HashMap, fs::read_to_string, net::IpAddr};
pub mod packet;
use crate::packet::{DnsPacket, Header, ParsedSection, Query, Record, Section};
fn handle_section(section: Section, buf: &Vec<u8>, dns_packet: &mut DnsPacket) -> ParsedSection {
    match section {
        Section::Header => Header::new(&buf, dns_packet),
        Section::Question => Query::new(buf.to_vec(), dns_packet),
        // Section::Answer => ,
        Section::Authority => ParsedSection::Authority,
        Section::Additional => ParsedSection::Additional,
        _ => ParsedSection::Additional,
    }
}
fn get_hostnames_to_block(filename: &str) -> Vec<String> {
    let mut result = Vec::new();
    for rawline in read_to_string(filename).unwrap().lines() {
        match rawline.chars().count() {
            1.. => match rawline.chars().nth(0).unwrap() {
                '#' => (),
                _ => result.push(String::from(rawline)),
            },
            _ => (),
        };
    }
    result
}

fn lookup_hostname(hostname: &String) -> Result<Vec<IpAddr>> {
    let ips = lookup_host(hostname)?;
    Ok(ips)
}

fn handle_client(message_buf: Vec<u8>, dns_records: &HashMap<String, Vec<IpAddr>>) -> Vec<u8> {
    let mut dns_packet = DnsPacket::new(&message_buf);
    // Extract header from buffer
    let h = handle_section(Section::Header, &message_buf, &mut dns_packet);
    // If header is DNS query, parse the queries - if not, forward the packet
    // #TODO - implement packet forwarding for responses
    if let ParsedSection::Header(mut header) = h {
        // If packet is a DNS query:
        if !header.response {
            // Start building response packet:
            header.response = true;
            header.ancount = 1;
            dns_packet.set_header(header);
            // Get question from packet
            let q = handle_section(Section::Question, &message_buf, &mut dns_packet);

            if let ParsedSection::Question((question)) = q {
                dns_packet.set_query(&question);
                let r = Record::new(&question, dns_records);
                dns_packet.set_answer(&r);
                // if Option::is_some(&dns_packet.authority) {
                //     todo!();
                // } else {
                //     todo!();
                // }
                // if Option::is_some(&dns_packet.additional) {
                //     todo!();
                // } else {
                //     todo!();
                // }
            }
        }
    }

    dns_packet.build_packet()
}

fn main() -> Result<()> {
    let lines: Vec<String> = get_hostnames_to_block("blockList.conf");
    let mut dns_records = HashMap::new();
    for line in lines {
        if let Ok(ips) = lookup_hostname(&line) {
            dns_records.insert(line, ips);
        };
    }

    let socket = UdpSocket::bind("127.0.0.1:53")?;
    println!("DNS server running on 127.0.0.1:53");

    loop {
        // DNS packets are limited to 512 bytes
        let mut buf = [0; 512];
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf).expect("Didn't receive data");
        let filled_buf = Vec::from(buf.get(..number_of_bytes).unwrap());
        let result = handle_client(filled_buf, &dns_records);
        socket.send_to(&result, src_addr).expect("error");
    }
}
