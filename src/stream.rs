#![cfg(feature = "tokio")]

use std::sync::{Arc, mpsc::TryRecvError};

use futures::{Stream, StreamExt};
use tokio::sync::Notify;

use crate::{Capture, CaptureBackend, Packet};

impl Capture {
    /// Get a stream of packets from the capture.
    ///
    /// This is only available if the `tokio` feature is enabled.
    pub fn stream(mut self) -> std::io::Result<impl Stream<Item = Packet> + Unpin> {
        let notify = Arc::new(Notify::new());

        // Start before setting notify as Consumer needs to be created first.
        // It's okay if some notify permits are missed, since we will try_recv first anyways.
        self.start()?; 
        self.backend.set_notify(notify.clone());

        Ok(async_stream::stream! {
            loop {
                match self.backend.try_next_packet() {
                    Ok(packet) => yield packet,
                    Err(TryRecvError::Empty) => {
                        notify.notified().await;
                    }
                    Err(TryRecvError::Disconnected) => break,
                }
            }
        }
        .boxed())
    }
}
