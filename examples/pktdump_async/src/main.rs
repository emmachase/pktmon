use std::time::Duration;

use futures::StreamExt;
use pktmon::{
    Capture,
    filter::{PktMonFilter, TransportProtocol},
};

#[tokio::main]
async fn main() {
    colog::default_builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let mut sniffer = Capture::new().unwrap();

    sniffer
        .add_filter(PktMonFilter {
            name: "UDP Traffic".to_string(),
            transport_protocol: Some(TransportProtocol::UDP),

            ..PktMonFilter::default()
        })
        .unwrap();

    let mut stream = sniffer.stream().unwrap().boxed().fuse();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    loop {
        tokio::select! {
            packet = stream.select_next_some() => {
                println!("{:?}", packet.payload);
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }
}
