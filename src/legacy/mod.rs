use std::{
    fmt::Debug,
    io,
    sync::mpsc::{Receiver, RecvError, RecvTimeoutError, TryRecvError},
    time::Duration,
};

use driver::Driver;
use etw::{EtwConsumer, EtwSession};
use log::{debug, info};

use crate::{CaptureBackend, Packet, filter::PktMonFilter, util::install_shutdown_hook};

mod c_filter;
mod driver;
mod etw;

pub use etw::EtlConsumer;

pub struct LegacyBackend {
    driver: Driver,
    etw: EtwSession,
    consumer: Option<EtwConsumer>,
    receiver: Option<Receiver<Packet>>,
    running: bool,
    #[cfg(feature = "tokio")]
    notify: Option<std::sync::Arc<tokio::sync::Notify>>,
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
        install_shutdown_hook(|| {
            EtwSession::default().close().ok();
            if let Ok(driver) = Driver::new() {
                driver.unload().ok();
            }
        });

        Ok(Self {
            driver: Driver::new()?,
            etw: EtwSession::new()?,
            consumer: None,
            receiver: None,
            running: false,

            #[cfg(feature = "tokio")]
            notify: Some(std::sync::Arc::new(tokio::sync::Notify::new())),
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

        #[cfg(feature = "tokio")]
        let (consumer, receiver) = EtwConsumer::new(self.notify.clone())?;

        #[cfg(not(feature = "tokio"))]
        let (consumer, receiver) = EtwConsumer::new()?;

        self.consumer = Some(consumer);
        self.receiver = Some(receiver);

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

        self.receiver.take();

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
        if let Some(ref receiver) = self.receiver {
            receiver.recv()
        } else {
            Err(RecvError)
        }
    }

    /// Get the next packet from the capture with a timeout.
    ///
    /// Returns an error if the capture isn't running or if the timeout is reached.
    fn next_packet_timeout(&self, timeout: Duration) -> Result<Packet, RecvTimeoutError> {
        if let Some(ref receiver) = self.receiver {
            receiver.recv_timeout(timeout)
        } else {
            Err(RecvTimeoutError::Disconnected)
        }
    }

    fn try_next_packet(&self) -> Result<Packet, TryRecvError> {
        if let Some(ref receiver) = self.receiver {
            receiver.try_recv()
        } else {
            Err(TryRecvError::Disconnected)
        }
    }

    #[cfg(feature = "tokio")]
    fn notify(&self) -> Option<std::sync::Arc<tokio::sync::Notify>> {
        self.notify.clone()
    }
}
