use dotenv::dotenv;
use std::io::{Result, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::read_to_string,
    thread,
};
pub mod packet;
use crate::packet::{DnsPacket, FalseRecord, Header, Query};

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

fn handle_client(
    socket: &UdpSocket,
    message_buf: Vec<u8>,
    blocked_sites: &HashSet<String>,
    default_dns_server: &String,
) -> (String, Option<Vec<u8>>) {
    // Initialize response (will stay None if packet is query and is forwarded to gateway)
    let mut response = None;
    // packet to be returned if query is in block list OR packet is a response from GW
    let mut dns_packet = DnsPacket::new(&message_buf);

    // Extract header from buffer
    let mut header: Header = Header::new(&message_buf, &mut dns_packet);

    let id = header.id.to_string();
    // If header is DNS query, parse the queries - if not, forward the packet
    // back to the original requestor
    if !header.response {
        println!("Incoming query!");
        // Get query from packet and instantiate struct
        let query = Query::new(message_buf.to_vec(), &mut dns_packet);
        println!("Query: {:?}", &query.name_str);
        // If query is in block list, build "false" packet to send to requestor
        if blocked_sites.contains(&query.name_str) {
            // Build fake response packet
            header.response = true;
            header.ancount = 1;
            dns_packet.set_header(header);
            dns_packet.set_query(&query);
            let r: FalseRecord = FalseRecord::new(&query);
            dns_packet.set_answer(&r);
            response = Some(dns_packet.build_packet());
            thread::spawn(move || {
                let analytics_server = "127.0.0.1:49152";
                let mut stream: TcpStream = TcpStream::connect(analytics_server).unwrap();
                stream.write_all(&query.name_str.as_bytes()).unwrap();
                stream.shutdown(std::net::Shutdown::Both).unwrap();
            });
        } else {
            // If query is not in block list, forward it to the gateway
            let default_server = default_dns_server.to_owned() + ":53";
            socket.send_to(&message_buf, default_server).expect("error");
            // Note we are not waiting for a response here, instead, ID of
            // return type will be stored in hash map along with requestor's IP
        };
    } else {
        // if message is response
        response = Some(message_buf);
    }

    (id, response)
}

fn main() -> Result<()> {
    // Variable initialization
    dotenv().ok();
    let default_dns_server = env::var("DEFAULT_DNS_SERVER").unwrap();
    // Get blocked IPs
    let lines: Vec<String> = get_hostnames_to_block("blockList.conf.prod");
    let mut dns_records = HashSet::new();
    for line in lines {
        dns_records.insert(line);
    }

    // Initialize UDP server
    let socket = UdpSocket::bind("0.0.0.0:53")?;

    // Create hashmap for temp storage of forwarded packets: {request ID: requestor's IP address}
    let mut clients: HashMap<String, SocketAddr> = HashMap::new(); // DNS QUERY ID: IP ADDRESS THAT REQUESTED IT
    loop {
        println!("{:?}", clients);
        // DNS packets are limited to 512 bytes
        let mut buf = [0; 512];
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf).expect("Didn't receive data");
        let filled_buf = Vec::from(buf.get(..number_of_bytes).unwrap());
        let result = handle_client(&socket, filled_buf, &dns_records, &default_dns_server);
        match result.1 {
            Some(r) => {
                println!("Response received for ID: {:?}", result.0);
                if clients.contains_key(&result.0) {
                    println!(
                        "Response is for previous entry in hash map. Sending to {:?}",
                        &clients.get(&result.0).unwrap()
                    );
                    socket.send_to(&r, &clients.get(&result.0).unwrap())?;
                    clients.remove_entry(&result.0);
                } else {
                    socket.send_to(&r, src_addr)?;
                }
            }
            None => {
                println!(
                    "No response received. Inserting ID {} into hash map with source address {:?}",
                    result.0, src_addr
                );
                clients.insert(result.0, src_addr);
            }
        }
    }
}
