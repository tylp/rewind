use rewind::Rewinder;
use tracing::{info, Level};

fn init_log() {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
}

#[tokio::main]
async fn main() {
    init_log();

    let rewind = Rewinder::new("pcap/single.pcapng".to_string()).unwrap();
    let remote_hosts = rewind.get_remote_hosts();
    let local_hosts = rewind.get_local_hosts();
    let replay_packets = rewind.get_replay_packets();

    info!("Local hosts: {:?}", local_hosts);
    info!("Remote hosts: {:?}", remote_hosts);

    for packet in replay_packets {
        info!("-- Packet #{}", packet.get_number());
        info!("time: {:?}", packet.get_time());
        info!("delay: {:?}", packet.get_delay());
        info!("source: {:?}", packet.get_local_host());
        info!("destination: {:?}", packet.get_remote_host());
        info!("data: {:?}", packet.get_packet_data());
        info!("status: {:?}", packet.get_status());
    }
}
