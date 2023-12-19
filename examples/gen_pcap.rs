use tracing::Level;

fn init_log() {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
}

/// Generates a pcap that sends a simple tcp and upd packet from localhost to
/// another host on the lan.
#[tokio::main]
async fn main() {
    init_log();

    let device = pcap::Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    // Setup Capture
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // open savefile using the capture
    let mut savefile = cap.savefile("pcap/test.pcap").unwrap();

    cap.filter("host 127.0.0.1", true).unwrap();

    while let Ok(packet) = cap.next_packet() {
        println!("got packet! {:?}", packet);
        // write the packet to the savefile
        savefile.write(&packet);
    }
}
