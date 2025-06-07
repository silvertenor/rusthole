use dns_lookup::lookup_host;
use std::io::Result;
use std::net::UdpSocket;
use std::{collections::HashMap, fs::read_to_string, net::IpAddr};

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

fn get_dns_query_and_response(mut message_buf: Vec<u8>) -> (String, Vec<u8>) {
    let mut query = String::new();
    let mut response_name = vec![];
    'outer: loop {
        let mut i: u8 = 1;
        response_name.push(message_buf[0]);
        for j in i..=message_buf[0] {
            query.push(message_buf[j as usize].to_ascii_lowercase() as char);
            response_name.push(message_buf[j as usize]);
            i = j + 1;
        }
        message_buf = message_buf.get((i as usize)..).unwrap().to_vec();
        if message_buf[0] == 0 {
            break 'outer;
        } else {
            query.push('.');
        }
    }
    response_name.extend_from_slice(&[0]);
    (query, response_name)
}

fn build_response(
    dns_records: &HashMap<String, Vec<IpAddr>>,
    query: String,
    response_name: Vec<u8>,
) -> Vec<u8> {
    let mut response: Vec<u8> = vec![0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    // response.extend_from_slice(query.as_bytes());
    // println!("{response_name:?}");
    response.extend_from_slice(&response_name);
    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let mut first: u8 = 127;
    let mut second: u8 = 0;
    let mut third: u8 = 0;
    let mut fourth: u8 = 0;
    if dns_records.contains_key(&query) {
        let ip_addr = &dns_records.get(&query).unwrap().get(0).unwrap().to_string();
        let split: Vec<&str> = ip_addr.split('.').collect();
        first = split.get(0).unwrap().parse().unwrap();
        second = split.get(1).unwrap().parse().unwrap();
        third = split.get(2).unwrap().parse().unwrap();
        fourth = split.get(3).unwrap().parse().unwrap();
    }

    response.extend_from_slice(&[
        0xC0, 0x0C, // Name (pointer to offset 12)
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3C, // TTL = 60s
        0x00, 0x04, // RDLENGTH = 4
        first, second, third, fourth,
    ]);

    response
}
fn handle_client(mut message_buf: Vec<u8>, dns_records: &HashMap<String, Vec<IpAddr>>) -> Vec<u8> {
    let mut id_buf = vec![0u8; 2]; // two bytes for ID
    id_buf = message_buf[..2].to_vec();
    message_buf = message_buf.get(12..).unwrap().to_vec();
    let (query, response_name) = get_dns_query_and_response(message_buf);
    let response = build_response(dns_records, query, response_name);
    id_buf.extend_from_slice(&response);
    id_buf
}

fn main() -> Result<()> {
    let lines: Vec<String> = get_hostnames_to_block("blockList.conf");
    let mut dnsRecords = HashMap::new();
    for line in lines {
        if let Ok(ips) = lookup_hostname(&line) {
            dnsRecords.insert(line, ips);
        };
    }

    let socket = UdpSocket::bind("127.0.0.1:53")?;
    println!("DNS TCP server running on 127.0.0.1:53");

    loop {
        let mut buf = [0; 2048];
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf).expect("Didn't receive data");
        let filled_buf = Vec::from(buf.get(..number_of_bytes).unwrap());
        let result = handle_client(filled_buf, &dnsRecords);
        socket.send_to(&result, src_addr).expect("error");
    }
}
