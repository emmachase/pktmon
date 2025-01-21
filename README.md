# PktMon

PktMon is a library for capturing network packets on Windows using the
PktMon driver, which is included by default with Windows 10 and later.

See [here](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon)
for more information about the PktMon service.

## Features

- Easy-to-use high-level interface for packet capture
- Filter support for protocol, ports, IP addresses, and more

## Requirements

- Windows 10 or later
- Administrator privileges are required to talk to the PktMon service

## Installation

```bash
cargo add pktmon
```

Or add it to your `Cargo.toml`:

```toml
[dependencies]
pktmon = "0.1.0"
```

## Usage

```rust
use pktmon::{Capture, filter::{PktMonFilter, TransportProtocol}};

fn main() {
    // Create a new capture instance
    let mut capture = Capture::new().unwrap();

    // Add a filter to capture UDP traffic on port 1234
    capture.add_filter(PktMonFilter {
        name: "UDP Filter".to_string(),
        transport_protocol: Some(TransportProtocol::UDP),
        port: 1234.into(),

        ..PktMonFilter::default()
    }).unwrap();
    
    // Start capturing
    capture.start().unwrap();
    
    // Get and print the next packet
    let packet = capture.next_packet().unwrap();
    println!("{:?}", packet.payload);
    
    // Stop capturing
    capture.stop().unwrap();
    
    // Unload the driver when done
    capture.unload().unwrap();
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
