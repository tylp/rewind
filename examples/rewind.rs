use rewind::rewind;
use tracing::Level;

fn init_log() {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
}

#[tokio::main]
async fn main() {
    init_log();

    // let _parse = parse("pcap/capture.pcapng");
    let _rewind = rewind("pcap/capture.pcapng");
}
