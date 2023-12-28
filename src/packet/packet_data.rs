use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    tcp::TcpPacket,
    udp::UdpPacket,
};

#[derive(Debug)]
/// Enum representing the packet data for a UDP or TCP packet. Used to store
/// parsed packet contents in a common format.
pub enum ReplayPacketData {
    Udp(UdpPacket<'static>),
    Tcp(TcpPacket<'static>),
}

/// Implementation of the ReplayPacketData enum representing UDP and TCP packet data.
/// Used to store parsed packet contents in a common format.
impl ReplayPacketData {
    /// Converts raw packet buffer and protocol into a `ReplayPacketData` enum.
    ///
    /// Takes a `IpNextHeaderProtocol` value indicating UDP or TCP, and a buffer.
    /// Uses `pnet` to parse buffer into `UdpPacket` or `TcpPacket`.
    /// Returns `ReplayPacketData` variant with parsed packet, or error string.
    ///
    /// Part of packet decoding, converting buffers into structured Rust types.
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
