#![cfg(windows)]

use std::{io, sync::mpsc::RecvError, fmt::Debug};
use driver::Driver;
use etw::{EtwConsumer, EtwSession, Packet};
use filter::PktMonFilter;
use log::{debug, info};

mod util;
mod etw;
mod driver;
mod c_filter;
pub mod filter;

pub struct Sniffer {
    driver: Driver,
    etw: EtwSession,
    consumer: Option<EtwConsumer>,
    running: bool,
}

impl Debug for Sniffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sniffer {{ running: {:?} }}", self.running)
    }
}

impl Sniffer {
    pub fn new() -> io::Result<Self> {
        Ok(Self { 
            driver: Driver::new()?,
            etw: EtwSession::new()?,
            consumer: None,
            running: false,
        })
    }

    pub fn start(&mut self) -> io::Result<()> {
        if self.running {
            return Ok(());
        }

        debug!("Starting sniffer...");

        self.etw.activate()?;

        self.consumer = Some(EtwConsumer::new()?);

        self.driver.start_capture()?;
        self.running = true;

        info!("Sniffer started");
        
        Ok(())
    }

    pub fn stop(&mut self) -> io::Result<()> {
        if !self.running {
            return Ok(());
        }

        debug!("Stopping sniffer...");

        self.running = false;
        self.driver.stop_capture()?;
        self.etw.deactivate()?;
        
        if let Some(mut consumer) = self.consumer.take() {
            consumer.stop()?;
        }

        info!("Sniffer stopped");

        Ok(())
    }

    // Take self and drop it to ensure the driver isn't used after this
    pub fn unload(self) -> io::Result<()> {
        drop(self);

        Driver::unload()?;
        Ok(())
    }

    pub fn add_filter(&mut self, filter: PktMonFilter) -> io::Result<()> {
        self.driver.add_filter(filter)?;
        Ok(())
    }

    pub fn next_packet(&mut self) -> Result<Packet, RecvError> {
        if let Some(ref mut consumer) = self.consumer {
            consumer.receiver.recv()
        } else {
            Err(RecvError)
        }
    }
}

impl Drop for Sniffer {
    fn drop(&mut self) {
        self.stop().unwrap();
    }
}
