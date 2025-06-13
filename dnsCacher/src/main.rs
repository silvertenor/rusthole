use dns_lookup::lookup_host;
use std::io::Result;
use std::net::{SocketAddr, UdpSocket};
use std::{
    collections::{HashMap, HashSet},
    fs::read_to_string,
    net::IpAddr,
};
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

#[derive(Debug)]
struct ReturnType {
    id: String,
    response: Option<Vec<u8>>,
}
fn handle_client(
    socket: &UdpSocket,
    message_buf: Vec<u8>,
    dns_records: &HashSet<String>,
) -> ReturnType {
    let mut return_type = ReturnType {
        id: String::new(),
        response: None,
    };
    let mut dns_packet = DnsPacket::new(&message_buf);
    // Extract header from buffer
    let h = handle_section(Section::Header, &message_buf, &mut dns_packet);
    // If header is DNS query, parse the queries - if not, forward the packet
    if let ParsedSection::Header(mut header) = h {
        return_type.id = header.id.to_string();
        // If packet is a DNS query:
        if !header.response {
            println!("Incoming query!");
            // Get question from packet
            let q = handle_section(Section::Question, &message_buf, &mut dns_packet);

            if let ParsedSection::Question((question)) = q {
                println!("Query: {:?}", &question.name_str);
                if dns_records.contains(&question.name_str) {
                    // Start building response packet:
                    header.response = true;
                    header.ancount = 1;
                    dns_packet.set_header(header);
                    dns_packet.set_query(&question);
                    let r = Record::new(&question);
                    dns_packet.set_answer(&r);
                    return_type.response = Some(dns_packet.build_packet());
                } else {
                    println!("Query not in block list. Forwarding to gateway");
                    socket
                        .send_to(&message_buf, "192.168.50.1:53")
                        .expect("error");
                };
            }
        } else {
            // if message is response
            return_type.response = Some(message_buf);
        }
    }
    return_type
}

fn main() -> Result<()> {
    let lines: Vec<String> = get_hostnames_to_block("blockList.conf.prod");
    let mut dns_records = HashSet::new();
    let mut count = 0;
    for line in lines {
        println!("{}", count);
        count += 1;
        dns_records.insert(line);
    }

    let socket = UdpSocket::bind("0.0.0.0:53")?;
    println!("DNS server running on 0.0.0.0:53");
    let mut clients: HashMap<String, SocketAddr> = HashMap::new(); // DNS QUERY ID: IP ADDRESS THAT REQUESTED IT
    loop {
        println!("{:?}", clients);
        // DNS packets are limited to 512 bytes
        let mut buf = [0; 512];
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf).expect("Didn't receive data");
        let filled_buf = Vec::from(buf.get(..number_of_bytes).unwrap());
        let result = handle_client(&socket, filled_buf, &dns_records);
        match result.response {
            Some(r) => {
                println!("Response received for ID: {:?}", result.id);
                if clients.contains_key(&result.id) {
                    println!(
                        "Response is for previous entry in hash map. Sending to {:?}",
                        &clients.get(&result.id).unwrap()
                    );
                    socket.send_to(&r, &clients.get(&result.id).unwrap())?;
                    clients.remove_entry(&result.id);
                } else {
                    socket.send_to(&r, src_addr)?;
                }
            }
            None => {
                println!(
                    "No response received. Inserting ID {} into hash map with source address {:?}",
                    result.id, src_addr
                );
                clients.insert(result.id, src_addr);
            }
        }
    }
}
