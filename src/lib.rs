use anyhow::{bail, Error, Ok, Result};
use pcap::Capture;
use pnet::packet::{ip::IpNextHeaderProtocols, tcp::TcpPacket, udp::UdpPacket, Packet};
use std::{net::Ipv4Addr, time::Duration};
use tracing::{debug, error, info, warn};

#[derive(Debug)]
enum ReplayProtocol<'a> {
    Udp(UdpPacket<'a>),
    Tcp(TcpPacket<'a>),
}

#[derive(Debug)]
struct ReplayPacket<'a> {
    time: Duration,
    delay: Duration,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    packet: ReplayProtocol<'a>,
}

impl<'a> ReplayPacket<'a> {
    pub fn new(
        time: Duration,
        delay: Duration,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        packet: ReplayProtocol<'a>,
    ) -> Self {
        ReplayPacket {
            time,
            delay,
            source,
            destination,
            packet,
        }
    }
}

/**
 * Replay each packet on the given pcap.
 */
pub fn rewind(pcap: &str) -> Result<(), Error> {
    let mut capture = Capture::from_file(pcap)?;
    let mut transmition_vector: Vec<ReplayPacket> = Vec::new();

    // For each packet, establish
    // - The timestamp
    // - The source
    // - The destination
    let packet = capture.next_packet()?;

    let ethernet_packet = pnet::packet::ethernet::EthernetPacket::new(packet.data).unwrap();
    let ipv4_packet = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()).unwrap();
    let proto = ipv4_packet.get_next_level_protocol();

    let source = ipv4_packet.get_source();
    let destination = ipv4_packet.get_destination();

    // Start time reference
    let timestamp = packet.header.ts;
    let seconds = timestamp.tv_sec as u64;
    let nanos = (timestamp.tv_usec as u64) * 1000;

    let time = Duration::new(seconds, nanos as u32);
    let mut delay = Duration::new(0, 0);

    // After the second frame, calculate the delta between the previous frame and the current one
    if !transmition_vector.is_empty() {
        let previous_time = transmition_vector.last().unwrap().time;
        delay = time - previous_time;
    }

    // Now check protocols
    if proto == IpNextHeaderProtocols::Tcp {
        let tcp_packet = pnet::packet::tcp::TcpPacket::new(ipv4_packet.payload()).unwrap();
        let rp = ReplayPacket::new(
            time,
            delay,
            source,
            destination,
            ReplayProtocol::Tcp(tcp_packet),
        );

        transmition_vector.push(rp);
    }

    if proto == IpNextHeaderProtocols::Udp {
        let udp_packet = pnet::packet::udp::UdpPacket::new(ipv4_packet.payload()).unwrap();
        let rp = ReplayPacket::new(
            time,
            delay,
            source,
            destination,
            ReplayProtocol::Udp(udp_packet),
        );

        transmition_vector.push(rp);
    }

    debug!("{:?}", transmition_vector);

    Ok(())
}
