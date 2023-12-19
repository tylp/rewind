use anyhow::{bail, Error, Result};
use pcap::Capture;
use pnet::{
    datalink,
    packet::{
        ip::{
            IpNextHeaderProtocol,
            IpNextHeaderProtocols::{self},
        },
        tcp::TcpPacket,
        udp::UdpPacket,
        Packet,
    },
};
use std::{net::Ipv4Addr, time::Duration};
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub enum ReplayPacketData<'a> {
    Udp(UdpPacket<'a>),
    Tcp(TcpPacket<'a>),
}

impl<'a> ReplayPacketData<'a> {
    pub fn from_proto(
        proto: IpNextHeaderProtocol,
        buffer: &'a [u8],
    ) -> Result<ReplayPacketData<'a>, &'static str> {
        match proto {
            IpNextHeaderProtocols::Tcp => TcpPacket::new(buffer)
                .map(ReplayPacketData::Tcp)
                .ok_or("Invalid TCP packet"),
            IpNextHeaderProtocols::Udp => UdpPacket::new(buffer)
                .map(ReplayPacketData::Udp)
                .ok_or("Invalid UDP packet"),
            _ => Err("Unsupported protocol"),
        }
    }
}

pub enum ReplayPacketStatus {
    Sent,
    NotSent,
    Failed,
}

#[derive(Debug)]
pub struct ReplayPacket<'a> {
    time: Duration,
    delay: Duration,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    packet: ReplayPacketData<'a>,
}

impl<'a> ReplayPacket<'a> {
    pub fn new(
        time: Duration,
        delay: Duration,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        packet: ReplayPacketData<'a>,
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
    let mut remote_addresses: Vec<Ipv4Addr> = Vec::new();
    let local_addresses: Vec<Ipv4Addr> = load_local_addresses();

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

    // Add the destination to the list of required connections if not present. Excludes local adress
    add_remote_address(&mut remote_addresses, &local_addresses, source, destination);

    // Start time reference
    let timestamp = packet.header.ts;
    let seconds = timestamp.tv_sec as u64;
    let nanos = (timestamp.tv_usec as u64) * 1000;

    let time = Duration::new(seconds, nanos as u32);
    let mut delay = Duration::new(0, 0);

    // After the second frame, calculate the delta between the previous frame and the current one
    if let Some(last_transmission) = transmition_vector.last() {
        let previous_time = last_transmission.time;
        delay = time - previous_time;
    }

    // Generate packet from the payload
    let replay_packet_data = match ReplayPacketData::from_proto(proto, ipv4_packet.payload()) {
        Ok(p) => p,
        Err(_) => todo!(),
    };

    transmition_vector.push(ReplayPacket::new(
        time,
        delay,
        source,
        destination,
        replay_packet_data,
    ));

    debug!("Packets: {:?}", transmition_vector);
    debug!("Remote hosts: {:?}", remote_addresses);
    debug!("Local hosts: {:?}", local_addresses);

    Ok(())
}

/// Add the remote host to the remote host's vec.
fn add_remote_address(
    remote_addresses: &mut Vec<Ipv4Addr>,
    local_addresses: &[Ipv4Addr],
    source: Ipv4Addr,
    destination: Ipv4Addr,
) {
    for &address in &[source, destination] {
        if !remote_addresses.contains(&address) && !local_addresses.contains(&address) {
            remote_addresses.push(address);
        }
    }
}

/// Retreive all the local addresses on all the network interfaces on this host.
fn load_local_addresses() -> Vec<Ipv4Addr> {
    datalink::interfaces()
        .into_iter()
        .flat_map(|iface| iface.ips)
        .filter_map(|ip| {
            if let pnet::ipnetwork::IpNetwork::V4(ipv4_network) = ip {
                Some(ipv4_network.ip())
            } else {
                None
            }
        })
        .collect()
}
