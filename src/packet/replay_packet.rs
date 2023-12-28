use std::time::Duration;

use super::{ReplayPacketData, ReplayPacketHost, ReplayPacketStatus};

#[derive(Debug)]
/// Represents a packet captured during replay. Contains metadata like packet number, timestamps, etc.
pub struct ReplayPacket {
    number: u64,
    time: Duration,
    delay: Duration,
    source: ReplayPacketHost,
    destination: ReplayPacketHost,
    packet: ReplayPacketData,
    status: ReplayPacketStatus,
}

/// Implementation of ReplayPacket struct which represents a packet captured during replay.
/// Contains metadata like packet number, timestamps, source/destination hosts etc.
/// Provides methods to access the packet metadata fields.
impl ReplayPacket {
    /// Constructs a new ReplayPacket with the given fields.
    pub fn new(
        number: u64,
        time: Duration,
        delay: Duration,
        source: ReplayPacketHost,
        destination: ReplayPacketHost,
        packet: ReplayPacketData,
        status: ReplayPacketStatus,
    ) -> Self {
        ReplayPacket {
            number,
            time,
            delay,
            source,
            destination,
            packet,
            status,
        }
    }

    /// Returns the packet number of this ReplayPacket.
    pub fn get_number(&self) -> u64 {
        self.number
    }

    /// Returns the timestamp when this packet was originally captured, relative to the start of the replay.
    pub fn get_time(&self) -> Duration {
        self.time
    }

    /// Returns the delay of this ReplayPacket, which is the time elapsed between
    /// when the packet was originally sent and when it was replayed.
    pub fn get_delay(&self) -> Duration {
        self.delay
    }

    /// Returns a reference to the source Host of this ReplayPacket.
    pub fn get_local_host(&self) -> &ReplayPacketHost {
        &self.source
    }

    /// Returns a reference to the destination Host of this ReplayPacket.
    pub fn get_remote_host(&self) -> &ReplayPacketHost {
        &self.destination
    }

    /// Returns a reference to the ReplayPacketData contained in this ReplayPacket.
    pub fn get_packet_data(&self) -> &ReplayPacketData {
        &self.packet
    }

    /// Returns a reference to the status of this ReplayPacket.
    pub fn get_status(&self) -> &ReplayPacketStatus {
        &self.status
    }
}
