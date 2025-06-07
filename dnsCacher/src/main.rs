use dns_lookup::lookup_host;
use std::io::{IoSlice, Read, Result, Write};
use std::net::{TcpListener, TcpStream};
use std::{collections::HashMap, fs::read_to_string, io::Error, net::IpAddr};

fn get_hostnames_to_block(filename: &str) -> Vec<String> {
    let mut result = Vec::new();
    // let mut counter = 0;
    for rawline in read_to_string(filename).unwrap().lines() {
        // if counter <= 200 {
        match rawline.chars().count() {
            1.. => match rawline.chars().nth(0).unwrap() {
                '#' => println!("Commented line!"),
                _ => result.push(String::from(rawline)),
            },
            _ => println!("Blank line!"),
        };
        // }
        println!("{rawline:?}");
        // counter += 1;
    }
    result
}

fn lookup_hostname(hostname: &String) -> Result<Vec<IpAddr>> {
    // println!("Looking up host: {hostname}");
    let ips = lookup_host(hostname)?;
    Ok(ips)
}

fn get_dns_query_and_response(mut message_buf: Vec<u8>) -> (String, Vec<u8>) {
    let mut query = String::new();
    let mut response_name = vec![];
    println!("{message_buf:?}");
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
    println!("{response_name:?}");
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
fn handle_client(mut stream: TcpStream, dns_records: &HashMap<String, Vec<IpAddr>>) -> Result<()> {
    // First, read the 2-byte length prefix
    let mut len_buf = [0u8; 2];
    if stream.read_exact(&mut len_buf).is_err() {
        println!("Client disconnected.");
        return Err(Error::last_os_error());
    }

    let full_msg_length = u16::from_be_bytes(len_buf) as usize;

    // Now read the actual DNS message
    let mut message_buf = vec![0u8; full_msg_length];
    let mut id_buf = vec![0u8; 2]; // two bytes for ID
    stream.read_exact(&mut message_buf)?;

    println!("\nReceived DNS query ({} bytes):", full_msg_length);
    id_buf = message_buf[..2].to_vec();
    message_buf = message_buf.get(12..).unwrap().to_vec();
    let (query, response_name) = get_dns_query_and_response(message_buf);
    let response = build_response(dns_records, query, response_name);
    id_buf.extend_from_slice(&response);
    stream.write_vectored(&[
        IoSlice::new(&(id_buf.len() as u16).to_be_bytes()),
        IoSlice::new(&id_buf),
    ])?;

    Ok(())
}

fn main() -> Result<()> {
    let lines: Vec<String> = get_hostnames_to_block("blockList.conf");
    let mut dnsRecords = HashMap::new();
    for line in lines {
        if let Ok(ips) = lookup_hostname(&line) {
            // println!("{:?}", ips);
            dnsRecords.insert(line, ips);
        };
    }

    let listener = TcpListener::bind("127.0.0.1:53")?; // Use port 5353 for non-root testing
    println!("DNS TCP server running on 127.0.0.1:53");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection from {}", stream.peer_addr()?);
                if let Err(e) = handle_client(stream, &dnsRecords) {
                    eprintln!("Error handling client: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    Ok(())
}
