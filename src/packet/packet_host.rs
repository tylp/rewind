use std::net::IpAddr;

#[derive(Debug)]
/// Represents a network host identified by an IP address and port number.
pub struct ReplayPacketHost {
    addr: IpAddr,
    port: u16,
}

/// Provides methods for creating a new `Host` instance and accessing its
/// address and port.
impl ReplayPacketHost {
    /// Creates a new `Host` instance from the given IP address and port number.
    pub fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }

    /// Returns the IP address of this `Host`.
    pub fn get_addr(&self) -> IpAddr {
        self.addr
    }

    /// Returns the port number of this `Host`.
    pub fn get_port(&self) -> u16 {
        self.port
    }
}
