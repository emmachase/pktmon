use pktmon::EtlCapture;
use std::env;

fn main() {
    colog::default_builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // Get file path from command line argument
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-etl-file>", args[0]);
        std::process::exit(1);
    }

    let etl_path = &args[1];
    println!("Reading packets from ETL file: {}", etl_path);

    // Create ETL capture reader
    let mut etl_capture = match EtlCapture::new(etl_path) {
        Ok(capture) => capture,
        Err(e) => {
            eprintln!("Failed to create ETL capture: {}", e);
            std::process::exit(1);
        }
    };

    // Process all packets
    match etl_capture.packets() {
        Ok(packets) => {
            println!("Successfully read {} packets from ETL file", packets.len());

            // Print packet information
            for (i, packet) in packets.iter().enumerate() {
                let type_str = match &packet.payload {
                    pktmon::PacketPayload::Unknown(_) => "Unknown",
                    pktmon::PacketPayload::Ethernet(_) => "Ethernet",
                    pktmon::PacketPayload::WiFi(_) => "WiFi",
                    pktmon::PacketPayload::IP(_) => "IP",
                    pktmon::PacketPayload::HTTP(_) => "HTTP",
                    pktmon::PacketPayload::TCP(_) => "TCP",
                    pktmon::PacketPayload::UDP(_) => "UDP",
                    pktmon::PacketPayload::ARP(_) => "ARP",
                    pktmon::PacketPayload::ICMP(_) => "ICMP",
                    pktmon::PacketPayload::ESP(_) => "ESP",
                    pktmon::PacketPayload::AH(_) => "AH",
                    pktmon::PacketPayload::L4Payload(_) => "L4Payload",
                };
                let payload = packet.payload.to_vec();
                println!("Packet [{}] #{}: {} bytes", type_str, i + 1, payload.len());

                // Print first 32 bytes of payload as hex dump
                if !payload.is_empty() {
                    println!("  First 32 bytes:");
                    let bytes_to_show = std::cmp::min(32, payload.len());
                    for (i, byte) in payload[..bytes_to_show].iter().enumerate() {
                        print!("{:02x} ", byte);
                        if (i + 1) % 16 == 0 {
                            println!();
                        }
                    }
                    println!();
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to process ETL file: {}", e);
            std::process::exit(1);
        }
    }
}
