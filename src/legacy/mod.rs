use std::{io, sync::mpsc::{RecvError, RecvTimeoutError}, time::Duration, fmt::Debug};

use driver::Driver;
use etw::{EtwConsumer, EtwSession};
use log::{debug, info};

use crate::{filter::PktMonFilter, CaptureBackend, Packet};

mod etw;
mod c_filter;
mod driver;

pub use etw::EtlConsumer;

pub struct LegacyBackend {
    driver: Driver,
    etw: EtwSession,
    consumer: Option<EtwConsumer>,
    running: bool,
}

impl Debug for LegacyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LegacyBackend {{ running: {:?} }}", self.running)
    }
}

impl LegacyBackend {
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
}

impl CaptureBackend for LegacyBackend {
    /// Start the capture.
    /// 
    /// Ensure to add filters before starting the capture.
    fn start(&mut self) -> io::Result<()> {
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
    fn stop(&mut self) -> io::Result<()> {
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
    fn unload(&mut self) -> io::Result<()> {
        Driver::unload(&self.driver)?;

        Ok(())
    }

    /// Add a filter to the capture.
    fn add_filter(&mut self, filter: PktMonFilter) -> io::Result<()> {
        self.driver.add_filter(filter)?;
        Ok(())
    }

    /// Get the next packet from the capture.
    /// 
    /// Returns an error if the capture isn't running.
    fn next_packet(&self) -> Result<Packet, RecvError> {
        if let Some(ref consumer) = self.consumer {
            consumer.receiver.recv()
        } else {
            Err(RecvError)
        }
    }

    /// Get the next packet from the capture with a timeout.
    /// 
    /// Returns an error if the capture isn't running or if the timeout is reached.
    fn next_packet_timeout(&self, timeout: Duration) -> Result<Packet, RecvTimeoutError> {
        if let Some(ref consumer) = self.consumer {
            consumer.receiver.recv_timeout(timeout)
        } else {
            Err(RecvTimeoutError::Disconnected)
        }
    }
}
