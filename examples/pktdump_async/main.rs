use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

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

    // while let Some(packet) = stream.next().await {
    //     println!("{:?}", packet.payload);
    // }

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

    // sniffer.start().unwrap();

    // let sniffer = Arc::new(Mutex::new(sniffer));
    // let running = Arc::new(AtomicBool::new(true));

    // let join_handle = {
    //     let running = running.clone();
    //     let sniffer = sniffer.clone();
    //     thread::spawn(move || {
    //         loop {
    //             let sniffer = sniffer.lock().unwrap();
    //             if let Ok(packet) = sniffer.next_packet_timeout(Duration::from_secs(1)) {
    //                 println!("{:?}", packet.payload);
    //             }

    //             if !running.load(Ordering::Relaxed) {
    //                 break;
    //             }
    //         }
    //     })
    // };

    // {
    //     let running = running.clone();
    //     let sniffer = sniffer.clone();
    //     std::thread::sleep(std::time::Duration::from_secs(5));

    //     running.store(false, Ordering::Relaxed);
    //     let mut sniffer = sniffer.lock().unwrap();
    //     sniffer.stop().unwrap();
    // }

    // join_handle.join().unwrap();

    // let sniffer = Arc::try_unwrap(sniffer).unwrap().into_inner().unwrap();
    // sniffer.unload().unwrap();
}
