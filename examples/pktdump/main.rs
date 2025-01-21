use std::{sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex}, thread};

use pktmon::{filter::{PktMonFilter, TransportProtocol}, Capture};

fn main() {
    colog::default_builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let mut sniffer = Capture::new().unwrap();

    sniffer.add_filter(PktMonFilter {
        name: "RQA - 1".to_string(),
        transport_protocol: Some(TransportProtocol::UDP),
        port: 23301.into(),

        ..PktMonFilter::default()
    }).unwrap();

    sniffer.add_filter(PktMonFilter {
        name: "RQA - 2".to_string(),
        transport_protocol: Some(TransportProtocol::UDP),
        port: 23302.into(),

        ..PktMonFilter::default()
    }).unwrap();

    sniffer.start().unwrap();

    let sniffer = Arc::new(Mutex::new(sniffer));
    let running = Arc::new(AtomicBool::new(true));

    let join_handle = {
        let running = running.clone();
        let sniffer = sniffer.clone();
        thread::spawn(move || {
            loop {
                let mut sniffer = sniffer.lock().unwrap();
                let packet = sniffer.next_packet().unwrap();
                println!("{:?}", packet.payload);

                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }
        })
    };

    {
        let running = running.clone();
        let sniffer = sniffer.clone();
        std::thread::sleep(std::time::Duration::from_secs(3));

        running.store(false, Ordering::Relaxed);
        let mut sniffer = sniffer.lock().unwrap();
        sniffer.stop().unwrap();
    }

    join_handle.join().unwrap();

    let sniffer = Arc::try_unwrap(sniffer).unwrap().into_inner().unwrap();
    sniffer.unload().unwrap();
}
