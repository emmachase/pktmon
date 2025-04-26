#![cfg(windows)]

//! # PktMon
//! 
//! PktMon is a library for capturing network packets on Windows using the
//! PktMon driver, which is included by default with Windows 10 and later.
//! 
//! See [here](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon)
//! for more information about the PktMon service.
//! 
//! ## Features
//! 
//! - Easy-to-use high-level interface for packet capture
//! - Filter support for protocol, ports, IP addresses, and more
//! - Support for reading packets from ETL files
//! 
//! ## Requirements
//! 
//! - Windows 10 or later
//! - Administrator privileges are required to talk to the PktMon service
//! 
//! ## Usage
//! 
//! See [Capture] for more information on live capture and [EtlCapture] for working with ETL files.
//! 
//! ```no_run
//! use pktmon::{Capture, filter::{PktMonFilter, TransportProtocol}};
//! 
//! fn main() {
//!     // Create a new capture instance
//!     let mut capture = Capture::new().unwrap();
//! 
//!     // Add a filter to capture UDP traffic on port 1234
//!     capture.add_filter(PktMonFilter {
//!         name: "UDP Filter".to_string(),
//!         transport_protocol: Some(TransportProtocol::UDP),
//!         port: 1234.into(),
//! 
//!         ..PktMonFilter::default()
//!     }).unwrap();
//!     
//!     // Start capturing
//!     capture.start().unwrap();
//!     
//!     // Get and print the next packet
//!     let packet = capture.next_packet().unwrap();
//!     println!("{:?}", packet.payload);
//!     
//!     // Stop capturing
//!     capture.stop().unwrap();
//!     
//!     // Unload the driver when done
//!     capture.unload().unwrap();
//! }
//! ```

use std::{io, sync::mpsc::{RecvError, RecvTimeoutError}, fmt::Debug, time::Duration, path::Path};
use legacy::{EtlConsumer, LegacyBackend};
use filter::PktMonFilter;
use log::{debug, info};
use realtime::RealTimeBackend;

mod util;
mod ctypes;
mod legacy;
mod realtime;
pub mod filter;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Packet {
    pub payload: Vec<u8>,
}

pub(crate) trait CaptureBackend: Debug + Send {
    fn start(&mut self) -> io::Result<()>;
    fn stop(&mut self) -> io::Result<()>;
    fn unload(&mut self) -> io::Result<()>;
    fn add_filter(&mut self, filter: PktMonFilter) -> io::Result<()>;
    fn next_packet(&self) -> Result<Packet, RecvError>;
    fn next_packet_timeout(&self, timeout: Duration) -> Result<Packet, RecvTimeoutError>;
}

/// A packet capture instance that uses the Windows PktMon driver to capture network traffic.
///
/// The `Capture` struct provides a high-level interface for capturing network packets using
/// the Windows PktMon driver. It manages the driver lifecycle, ETW session, and packet
/// consumption.
///
/// # Examples
///
/// ```no_run
/// use pktmon::{Capture, filter::{PktMonFilter, TransportProtocol}};
///
/// // Create a new capture instance
/// let mut capture = Capture::new().unwrap();
///
/// // Add a filter to capture UDP traffic on port 23301
/// capture.add_filter(PktMonFilter {
///     name: "UDP Filter".to_string(),
///     transport_protocol: Some(TransportProtocol::UDP),
///     port: 23301.into(),
///     ..PktMonFilter::default()
/// }).unwrap();
///
/// // Start capturing
/// capture.start().unwrap();
///
/// // Get the next packet
/// let packet = capture.next_packet().unwrap();
/// println!("{:?}", packet.payload);
///
/// // Stop capturing
/// capture.stop().unwrap();
///
/// // Unload the driver when done
/// capture.unload().unwrap();
/// ```
///
/// # Driver Lifecycle
///
/// The PktMon driver is loaded when creating a new `Capture` instance and remains loaded
/// until either:
/// - The `unload()` method is explicitly called
/// - The `Capture` instance is dropped
///
/// # Filters
///
/// Filters should be added before starting the capture using [`add_filter()`](Capture::add_filter).
/// Multiple filters can be added to capture different types of traffic.
/// If a packet matches any filter, it will be captured.
///
/// # Resource Cleanup
///
/// The `Capture` struct implements `Drop` to ensure proper cleanup of resources. When dropped:
/// 1. The capture is stopped if running
/// 2. The ETW session is deactivated
/// 3. The ETW consumer is stopped
///
/// However, it's recommended to explicitly call `stop()` and `unload()` when done to handle
/// any potential errors.
///
/// # Thread Safety
///
/// The `Capture` struct can be safely shared between threads using standard synchronization
/// primitives like `Arc<Mutex<Capture>>`. See the examples directory for a threaded example.
pub struct Capture {
    backend: Box<dyn CaptureBackend>,
    running: bool,
}

impl Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PktMon Capture {{ backend: {:?} }}", self.backend)
    }
}

impl Capture {
    /// Create a new capture instance.
    pub fn new() -> io::Result<Self> {
        // Try to use the RealTimeBackend first (Windows 11+)
        // Fall back to LegacyBackend if RealTimeBackend is not available
        let backend: Box<dyn CaptureBackend> = match RealTimeBackend::new() {
            Ok(backend) => Box::new(backend),
            Err(_) => Box::new(LegacyBackend::new()?),
        };

        Ok(Self {
            backend,
            running: false,
        })
    }

    /// Start the capture.
    /// 
    /// Ensure to add filters before starting the capture.
    pub fn start(&mut self) -> io::Result<()> {
        if self.running {
            return Ok(());
        }

        debug!("Starting capture...");

        self.backend.start()?;
        self.running = true;

        info!("Capture started");
        
        Ok(())
    }

    /// Stop the capture.
    /// 
    /// You may still receive packets after stopping the capture.
    pub fn stop(&mut self) -> io::Result<()> {
        if !self.running {
            return Ok(());
        }

        debug!("Stopping capture...");

        self.running = false;
        self.backend.stop()?;

        info!("Capture stopped");

        Ok(())
    }

    /// Unload the PktMon driver.
    /// 
    /// This will ensure the driver isn't used after this.
    pub fn unload(mut self) -> io::Result<()> {
        if self.running {
            self.stop()?;
        }

        self.backend.unload()?;

        // Take self and drop it to ensure the driver isn't used after this
        drop(self);

        Ok(())
    }

    /// Add a filter to the capture.
    pub fn add_filter(&mut self, filter: PktMonFilter) -> io::Result<()> {
        self.backend.add_filter(filter)?;
        Ok(())
    }

    /// Get the next packet from the capture.
    /// 
    /// Returns an error if the capture isn't running.
    pub fn next_packet(&self) -> Result<Packet, RecvError> {
        self.backend.next_packet()
    }

    /// Get the next packet from the capture with a timeout.
    /// 
    /// Returns an error if the capture isn't running or if the timeout is reached.
    pub fn next_packet_timeout(&self, timeout: Duration) -> Result<Packet, RecvTimeoutError> {
        self.backend.next_packet_timeout(timeout)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if self.running {
            if let Err(e) = self.stop() {
                debug!("Failed to stop capture: {:?}", e);
            }
        }
    }
}

/// A packet capture reader that processes packets from an ETL file.
///
/// The `EtlCapture` struct provides a high-level interface for reading network packets
/// from an Event Trace Log (ETL) file. This is useful for offline analysis of packets
/// captured using the PktMon driver or other ETW-based packet capture tools.
///
/// # Examples
///
/// ```no_run
/// use pktmon::EtlCapture;
/// use std::path::Path;
///
/// // Create a new ETL capture reader
/// let mut etl_capture = EtlCapture::new("C:\\path\\to\\capture.etl").unwrap();
///
/// // Get all packets from the file
/// let packets = etl_capture.packets().unwrap();
/// println!("Read {} packets from ETL file", packets.len());
///
/// // Process each packet
/// for packet in packets {
///     println!("Packet payload size: {}", packet.payload.len());
/// }
/// ```
///
/// # Resource Cleanup
///
/// The `EtlCapture` struct implements `Drop` to ensure proper cleanup of resources.
/// However, it's recommended to explicitly stop processing when done to handle any
/// potential errors.
pub struct EtlCapture {
    consumer: EtlConsumer,
}

impl Debug for EtlCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PktMon ETL Capture")
    }
}

impl EtlCapture {
    /// Create a new ETL capture reader for the specified ETL file.
    ///
    /// # Arguments
    ///
    /// * `etl_path` - Path to the ETL file to process
    ///
    /// # Returns
    ///
    /// A result containing the `EtlCapture` or an error.
    pub fn new<P: AsRef<Path>>(etl_path: P) -> io::Result<Self> {
        let consumer = match EtlConsumer::new(etl_path) {
            Ok(consumer) => consumer,
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };
        
        Ok(Self {
            consumer,
        })
    }
    
    /// Start processing the ETL file.
    ///
    /// This function starts processing the ETL file in a background thread.
    /// Packets can be retrieved using the `next_packet()` method.
    ///
    /// # Returns
    ///
    /// A result indicating success or an error.
    pub fn start(&mut self) -> io::Result<()> {
        match self.consumer.process() {
            Ok(()) => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
    
    /// Stop processing the ETL file.
    ///
    /// This function stops any ongoing processing and releases resources.
    ///
    /// # Returns
    ///
    /// A result indicating success or an error.
    pub fn stop(&mut self) -> io::Result<()> {
        match self.consumer.stop() {
            Ok(()) => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)), 
        }
    }
    
    /// Get the next packet from the ETL file.
    ///
    /// Returns an error if processing hasn't been started or if there are no more packets.
    ///
    /// # Returns
    ///
    /// A result containing the next packet or an error.
    pub fn next_packet(&self) -> Result<Packet, RecvError> {
        self.consumer.receiver.recv()
    }
    
    /// Process the ETL file synchronously and return all packets.
    ///
    /// This function blocks until the entire file has been processed or an error occurs.
    /// All packets are collected and returned in a vector.
    ///
    /// # Returns
    ///
    /// A result containing a vector of packets or an error.
    pub fn packets(&mut self) -> io::Result<Vec<Packet>> {
        match self.consumer.process_sync() {
            Ok(packets) => Ok(packets),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

impl Drop for EtlCapture {
    fn drop(&mut self) {
        if let Err(e) = self.consumer.stop() {
            debug!("Failed to stop ETL capture: {:?}", e);
        }
    }
}
