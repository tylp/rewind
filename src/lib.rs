use anyhow::{bail, Error, Result};
use pcap::Capture;
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, Ethernet},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4, Ipv4Option},
    tcp::{Tcp, TcpOption},
    udp::Udp,
    Packet,
};
use pnet_base::MacAddr;
use std::net::Ipv4Addr;
use tracing::{debug, error, info, warn};

/**
* Rewind the given pcap.
*
* A packet is divided into blocks.
* - The section header block, which defines the begining of a pcap packet.
* - The InterfaceDescritpionBlock, used to give hw infos
* - The enhanced/simple packet block, containing layers 2, 3 and 4 data.
*/
#[tracing::instrument]
pub fn rewind(pcap: &str) -> Result<(), Error> {
    info!("Analyzing {} capture file...", pcap);
    let mut capture = Capture::from_file(pcap)?;
    let mut packet_number = 1;

    let packet = capture.next_packet().unwrap();
    let dissected = dissect_packet(&packet, packet_number);

    // while let Ok(packet) = capture.next_packet() {
    //     let dissected = dissect_packet(&packet, packet_number);

    //     match dissected {
    //         Ok(_) => (),
    //         Err(e) => error!("{}", e),
    //     }

    //     packet_number += 1;
    // }

    Ok(())
}

fn dissect_packet(packet: &pcap::Packet, num: i32) -> Result<(), Error> {
    let header = packet.header;
    let data = packet.data;

    debug!(
        "----------------------- [{}] New Packet -----------------------",
        num
    );
    debug!("header: {:?}", header);
    debug!("payload: {:?}", data);

    let i = pnet::packet::ipv4::Ipv4Packet::new(&data[14..]).unwrap();

    info!("{:?}", i);

    let ethernet = get_layer_two(data)?;
    let l3 = get_layer_three(ethernet, data)?;
    get_layer_four(l3, data)?;

    debug!("------------------------------------------------------------------\n",);

    Ok(())
}

/**
 * Analyze the layer two data from the packet.
 */
fn get_layer_two(data: &[u8]) -> Result<Ethernet, Error> {
    // Check if data is long enough to contain an Ethernet header
    if data.len() < 14 {
        bail!("Layer two lenght ({}) is not long enough", data.len());
    }

    let dst: MacAddr = MacAddr(data[0], data[1], data[2], data[3], data[4], data[5]);
    let src: MacAddr = MacAddr(data[6], data[7], data[8], data[9], data[10], data[11]);
    let etht: EtherType = EtherType(u16::from_be_bytes([data[12], data[13]]));

    // Assuming the rest of the data is payload
    let pload = if data.len() > 14 {
        data[14..].to_vec()
    } else {
        Vec::new()
    };

    let eth = Ethernet {
        destination: dst,
        source: src,
        ethertype: etht,
        payload: pload,
    };

    debug!("# {:?}", eth);

    Ok(eth)
}

/**
 * Analyze the layer three data from the packet.
 */
fn get_layer_three(ethernet: Ethernet, data: &[u8]) -> Result<Ipv4, Error> {
    let ethertype = ethernet.ethertype;

    if ethertype != EtherTypes::Ipv4 {
        bail!("Protocol {} is not supported", ethertype);
    }

    if data.len() < 20 {
        bail!("Data slice is too short ({}) for IPV4 header", data.len());
    }

    let version = data[14] >> 4;
    let ihl = data[14] & 0x0F;
    let opts: Vec<Ipv4Option> = Vec::new();
    let mut payload_offset = 0;

    // If ihl > 5, we need to add ihl*32bits as options
    if ihl > 5 {
        payload_offset = (ihl * 4) as usize;
    }

    let ipv4 = Ipv4 {
        version,
        header_length: ihl,
        dscp: data[15] & 0xFC,
        ecn: data[15] & 0x03,
        total_length: u16::from_be_bytes([data[16], data[17]]),
        identification: u16::from_be_bytes([data[18], data[19]]),
        flags: data[19] & 0xE0,
        fragment_offset: u16::from_be_bytes([data[20] & 0x1F, data[21]]),
        ttl: data[22],
        next_level_protocol: IpNextHeaderProtocol::new(data[23]),
        checksum: u16::from_be_bytes([data[24], data[25]]),
        source: Ipv4Addr::new(data[26], data[27], data[28], data[29]),
        destination: Ipv4Addr::new(data[30], data[31], data[32], data[33]),
        options: opts,
        payload: data[payload_offset..].to_vec(),
    };

    debug!("# {:?}", ipv4);

    Ok(ipv4)
}

/**
 * Analyze the layer four data from the data.
 */

fn get_layer_four(ipv4: Ipv4, data: &[u8]) -> Result<(), Error> {
    // ethernet headerlen + ipv4 header len
    let offset = 14 + (ipv4.header_length * 4) as usize;
    let proto = ipv4.next_level_protocol;

    if offset > data.len() {
        bail!("Header lenght ({}) > data lenght ({})", offset, data.len());
    }

    if proto == IpNextHeaderProtocols::Tcp {
        let _tcp = handle_tcp(offset, data);
    }

    if proto == IpNextHeaderProtocols::Udp {
        let _udp = handle_udp(offset, data);
    }

    Ok(())
}

fn handle_tcp(offset: usize, data: &[u8]) -> Option<Tcp> {
    let data_offset = data[offset + 12] >> 4;
    let header_length = (data_offset * 4) as usize; // Total TCP header length in bytes

    // Ensure that the data slice is long enough to contain the full TCP header
    if data.len() < offset + header_length {
        return None;
    }

    let mut options = Vec::new();
    let mut payload = Vec::new();

    if data_offset > 5 {
        let options_start = offset + 20; // End of the standard TCP header
        let options_end = offset + header_length;
        options.extend_from_slice(&data[options_start..options_end]);
    }

    // The payload starts right after the TCP header
    if data.len() > offset + header_length {
        payload.extend_from_slice(&data[offset + header_length..]);
    }

    let opts: Vec<TcpOption> = vec![];

    let tcp = Tcp {
        source: u16::from_be_bytes([data[offset], data[offset + 1]]),
        destination: u16::from_be_bytes([data[offset + 2], data[offset + 3]]),
        sequence: u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]),
        acknowledgement: u32::from_be_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]),
        data_offset,
        reserved: data[offset + 12] & 0xF0, // Corrected to mask the reserved bits
        flags: data[offset + 13],
        window: u16::from_be_bytes([data[offset + 14], data[offset + 15]]),
        checksum: u16::from_be_bytes([data[offset + 16], data[offset + 17]]),
        urgent_ptr: u16::from_be_bytes([data[offset + 18], data[offset + 19]]),
        options: opts,
        payload,
    };

    debug!("# {:?}", tcp);

    Some(tcp)
}

fn handle_udp(offset: usize, data: &[u8]) -> Option<Udp> {
    let udp = Udp {
        source: u16::from_be_bytes([data[offset], data[offset + 1]]),
        destination: u16::from_be_bytes([data[offset + 3], data[offset + 4]]),
        length: u16::from_be_bytes([data[offset + 5], data[offset + 6]]),
        checksum: u16::from_be_bytes([data[offset + 7], data[offset + 8]]),
        payload: data[offset + 9..].to_vec(),
    };

    debug!("# {:?}", udp);

    Some(udp)
}
