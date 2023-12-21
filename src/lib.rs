use anyhow::{Error, Result};
use pcap::{Capture, Offline};
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
use std::{collections::HashSet, net::IpAddr, time::Duration};

#[derive(Debug)]
pub enum ReplayPacketData {
    Udp(UdpPacket<'static>),
    Tcp(TcpPacket<'static>),
}

impl ReplayPacketData {
    /// Converts the given buffer to its corresponding packet type using the given proto.
    pub fn from_proto(
        proto: IpNextHeaderProtocol,
        buffer: Vec<u8>,
    ) -> Result<ReplayPacketData, &'static str> {
        match proto {
            IpNextHeaderProtocols::Tcp => TcpPacket::owned(buffer)
                .map(ReplayPacketData::Tcp)
                .ok_or("Invalid TCP packet"),
            IpNextHeaderProtocols::Udp => UdpPacket::owned(buffer)
                .map(ReplayPacketData::Udp)
                .ok_or("Invalid UDP packet"),
            _ => Err("Unsupported protocol"),
        }
    }
}

#[derive(Debug)]
pub enum ReplayPacketStatus {
    Sent,
    NotSent,
    Failed,
}

#[derive(Debug)]
pub struct Host {
    addr: IpAddr,
    port: u16,
}

#[derive(Debug)]
pub struct ReplayPacket {
    time: Duration,
    delay: Duration,
    source: Host,
    destination: Host,
    packet: ReplayPacketData,
    status: ReplayPacketStatus,
}

impl ReplayPacket {
    pub fn new(
        time: Duration,
        delay: Duration,
        source: Host,
        destination: Host,
        packet: ReplayPacketData,
        status: ReplayPacketStatus,
    ) -> Self {
        ReplayPacket {
            time,
            delay,
            source,
            destination,
            packet,
            status,
        }
    }

    pub fn get_local_host(&self) {}
}

pub struct Rewinder {
    tx_vec: Vec<ReplayPacket>,
    remote_hosts: HashSet<IpAddr>,
    local_hosts: HashSet<IpAddr>,
}

impl Rewinder {
    /// Initialize a handle from the given pcap.
    /// The operation is blocking while the pcap parsing is not done.
    pub fn new(file: String) -> Result<Self, Error> {
        let mut capture = Capture::from_file(file)?;
        let tx_vec: Vec<ReplayPacket> = Rewinder::init_pcap(&mut capture);
        let local_hosts: HashSet<IpAddr> = Rewinder::init_local_hosts();
        let remote_hosts: HashSet<IpAddr> = Rewinder::extract_remote_hosts(&tx_vec, &local_hosts);

        Ok(Rewinder {
            tx_vec,
            remote_hosts,
            local_hosts,
        })
    }

    /// Extract every remote host address from the pcap. If an address is already identified
    /// as a local host it will not include it.
    fn extract_remote_hosts(
        packets: &[ReplayPacket],
        local_hosts: &HashSet<IpAddr>,
    ) -> HashSet<IpAddr> {
        packets
            .iter()
            .filter(|packet| !local_hosts.contains(&packet.destination.addr))
            .map(|p| p.destination.addr)
            .collect()
    }

    // Initialise the replay packets using the pcap
    fn init_pcap(capture: &mut Capture<Offline>) -> Vec<ReplayPacket> {
        let mut tx_packets: Vec<ReplayPacket> = Vec::new();

        // Loop through each packet
        while let Ok(packet) = capture.next_packet() {
            let ethernet_packet = pnet::packet::ethernet::EthernetPacket::new(packet.data).unwrap();

            // Assume we only do ipv4
            let ipv4_packet =
                pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()).unwrap();

            // Get a copy using .to_vec() since .payload() returns a &[u8] and so using clone would return a &[u8] also.
            let payload: Vec<u8> = ipv4_packet.payload().to_vec();

            let proto: IpNextHeaderProtocol = ipv4_packet.get_next_level_protocol();
            let source_ip: IpAddr = IpAddr::V4(ipv4_packet.get_source());
            let destination_ip: IpAddr = IpAddr::V4(ipv4_packet.get_destination());

            // Start time reference
            let timestamp = packet.header.ts;
            let seconds = timestamp.tv_sec as u64;
            let nanos = (timestamp.tv_usec as u64) * 1000;

            let time = Duration::new(seconds, nanos as u32);
            let mut delay = Duration::new(0, 0);

            // After the second frame, calculate the delta between the previous frame and the current one
            if let Some(last_transmission) = tx_packets.last() {
                let previous_time = last_transmission.time;
                delay = time - previous_time;
            }

            let tcp_packet = TcpPacket::owned(ipv4_packet.payload().to_vec()).unwrap();
            let source_port = tcp_packet.get_source();
            let destination_port = tcp_packet.get_destination();

            // Generate packet from the payload
            let replay_packet_data = match ReplayPacketData::from_proto(proto, payload) {
                Ok(p) => p,
                Err(_) => todo!(),
            };

            tx_packets.push(ReplayPacket::new(
                time,
                delay,
                Host {
                    addr: source_ip,
                    port: source_port,
                },
                Host {
                    addr: destination_ip,
                    port: destination_port,
                },
                replay_packet_data,
                ReplayPacketStatus::NotSent,
            ));
        }

        tx_packets
    }

    /// Return the list of remote ip addresses identified in the given capture file
    pub fn get_remote_hosts(&self) -> HashSet<IpAddr> {
        self.remote_hosts.clone()
    }

    pub fn get_local_hosts(&self) -> HashSet<IpAddr> {
        self.local_hosts.clone()
    }

    pub fn get_replay_packets(&self) -> &Vec<ReplayPacket> {
        &self.tx_vec
    }

    /// Returns the list of local ip addresses
    fn init_local_hosts() -> HashSet<IpAddr> {
        datalink::interfaces()
            .into_iter()
            .flat_map(|iface| iface.ips)
            .filter_map(|ip| {
                if let pnet::ipnetwork::IpNetwork::V4(ip4) = ip {
                    Some(IpAddr::V4(ip4.ip()))
                } else if let pnet::ipnetwork::IpNetwork::V6(ip6) = ip {
                    Some(IpAddr::V6(ip6.ip()))
                } else {
                    None
                }
            })
            .collect()
    }
}
