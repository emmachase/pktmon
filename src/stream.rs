#![cfg(feature = "tokio")]

use std::{pin::Pin, sync::{mpsc::TryRecvError, Arc}, task::{ready, Poll}};

use futures::Stream;
use tokio::{pin, sync::Notify};

use crate::{Capture, CaptureBackend, Packet};

struct PacketStream {
    notify: Arc<Notify>,
    capture: Capture,
}

impl Stream for PacketStream {
    type Item = Packet;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = Pin::into_inner(self);

        pin!(
            let notified = stream.notify.notified();
        );

        loop {
            match stream.capture.backend.try_next_packet() {
                Ok(packet) => return Poll::Ready(Some(packet)),
                Err(TryRecvError::Empty) => {
                    ready!(notified.as_mut().poll(cx));
                }
                Err(TryRecvError::Disconnected) => return Poll::Ready(None),
            }
        }
    }
}

impl Capture {
    /// Get a stream of packets from the capture.
    /// 
    /// This is only available if the `tokio` feature is enabled.
    pub fn stream(mut self) -> PacketStream {
        let notify = Arc::new(Notify::new());

        self.backend.set_notify(notify.clone());

        PacketStream { capture: self, notify }
    }
}
