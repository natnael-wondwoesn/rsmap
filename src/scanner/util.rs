use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::util;
use std::net::Ipv4Addr;

pub fn build_syn_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut tcp_buffer = [0u8; 40];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buffer[20..]).unwrap();

    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(12345);
    tcp_header.set_acknowledgement(0);
    tcp_header.set_data_offset(5); // 20 bytes
    tcp_header.set_flags(TcpFlags::SYN);
    tcp_header.set_window(64240);
    tcp_header.set_urgent_ptr(0);
    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    let mut ip_header = MutableIpv4Packet::new(&mut tcp_buffer[..20]).unwrap();

    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(40);
    ip_header.set_ttl(64);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ip);
    ip_header.set_destination(dst_ip);
    ip_header.set_identification(54321);
    ip_header.set_flags(Ipv4Flags::DontFragment);
    // let ip_checksum = util::checksum(&ip_header.packet(), 5);
    // ip_header.set_checksum(ip_checksum);

    tcp_buffer.to_vec()
}
