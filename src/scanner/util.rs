use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::util;
use std::net::Ipv4Addr;

pub fn build_syn_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    const IP_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 20;
    let mut buffer = vec![0u8; IP_HEADER_LEN + TCP_HEADER_LEN];

    // ----- TCP Header -----
    {
        let mut tcp = MutableTcpPacket::new(&mut buffer[IP_HEADER_LEN..]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(0x1234_5678);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5); // 20 bytes
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64_240);
        tcp.set_urgent_ptr(0);

        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
        tcp.set_checksum(checksum);
    }

    // ----- IPv4 Header -----
    {
        let mut ip = MutableIpv4Packet::new(&mut buffer[..IP_HEADER_LEN]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((IP_HEADER_LEN + TCP_HEADER_LEN) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_identification(0x1337);
        ip.set_flags(Ipv4Flags::DontFragment);
        let checksum = util::checksum(ip.packet(), 5);
        ip.set_checksum(checksum);
    }

    buffer
}
