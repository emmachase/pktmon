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
//! 
//! ## Requirements
//! 
//! - Windows 10 or later
//! - Administrator privileges are required to talk to the PktMon service
//! 
//! ## Usage
//! 
//! See [Capture] for more information.
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

use std::{io, sync::mpsc::{RecvError, RecvTimeoutError}, fmt::Debug, time::Duration};
use driver::Driver;
use etw::{EtwConsumer, EtwSession, Packet};
use filter::PktMonFilter;
use log::{debug, info};

mod util;
mod etw;
mod driver;
mod c_filter;
pub mod filter;

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
    driver: Driver,
    etw: EtwSession,
    consumer: Option<EtwConsumer>,
    running: bool,
}

impl Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PktMon Capture {{ running: {:?} }}", self.running)
    }
}


impl Capture {
    /// Create a new capture instance.
    /// 
    /// Loads the PktMon driver and creates an ETW session.
    pub fn new() -> io::Result<Self> {
        Ok(Self { 
            driver: Driver::new()?,
            etw: EtwSession::new()?,
            consumer: None,
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

        self.etw.activate()?;

        self.consumer = Some(EtwConsumer::new()?);

        self.driver.start_capture()?;
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
        self.driver.stop_capture()?;
        self.etw.deactivate()?;
        
        if let Some(mut consumer) = self.consumer.take() {
            consumer.stop()?;
        }

        info!("Capture stopped");

        Ok(())
    }

    /// Unload the PktMon driver.
    /// 
    /// This will ensure the driver isn't used after this.
    pub fn unload(self) -> io::Result<()> {
        // Take self and drop it to ensure the driver isn't used after this
        drop(self);

        Driver::unload()?;
        Ok(())
    }

    /// Add a filter to the capture.
    pub fn add_filter(&mut self, filter: PktMonFilter) -> io::Result<()> {
        self.driver.add_filter(filter)?;
        Ok(())
    }

    /// Remove all filters from the capture.
    pub fn remove_all_filters(&mut self) -> io::Result<()> {
        self.driver.remove_all_filters()?;
        Ok(())
    }

    /// Get the next packet from the capture.
    /// 
    /// Returns an error if the capture isn't running.
    pub fn next_packet(&self) -> Result<Packet, RecvError> {
        if let Some(ref consumer) = self.consumer {
            consumer.receiver.recv()
        } else {
            Err(RecvError)
        }
    }

    /// Get the next packet from the capture with a timeout.
    /// 
    /// Returns an error if the capture isn't running or if the timeout is reached.
    pub fn next_packet_timeout(&self, timeout: Duration) -> Result<Packet, RecvTimeoutError> {
        if let Some(ref consumer) = self.consumer {
            consumer.receiver.recv_timeout(timeout)
        } else {
            Err(RecvTimeoutError::Disconnected)
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop().unwrap();
    }
}
