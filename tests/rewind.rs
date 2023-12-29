use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use rewind::packet::ReplayPacketStatus;
use rewind::Rewinder;

#[tokio::test]
/// Test the init phase using a simple pcap file that only contains one packet.
pub async fn load_pcap_file_test() {
    let rewind = Rewinder::new("pcap/single.pcapng".to_string())
        .await
        .unwrap();
    let remote_hosts = rewind.get_remote_hosts();
    let replay_packets = rewind.get_replay_packets().first().unwrap();

    let mut rh: HashSet<IpAddr> = HashSet::new();
    rh.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

    assert_eq!(remote_hosts, rh);
    assert_eq!(replay_packets.get_number(), 0);
    assert_eq!(replay_packets.get_time(), Duration::ZERO);
    assert_eq!(replay_packets.get_delay(), Duration::ZERO);
    assert_eq!(
        replay_packets.get_local_host().get_addr(),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(replay_packets.get_local_host().get_port(), 443);
    assert_eq!(
        replay_packets.get_remote_host().get_addr(),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    );
    assert_eq!(replay_packets.get_remote_host().get_port(), 62446);
    let status = ReplayPacketStatus::NotSent;
    assert_eq!(replay_packets.get_status(), &status);
}
