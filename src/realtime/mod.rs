use std::{alloc::Layout, ffi::{c_void, OsString}, os::windows::ffi::OsStringExt, ptr::slice_from_raw_parts, sync::{mpsc, RwLock}, time::Duration};

use c_api::{PacketMonitorDataSourceList, PacketMonitorPacketType};
use log::{debug, error, info, trace, warn};
use windows::w;

use crate::{filter::PktMonFilter, CaptureBackend, Packet};

mod c_filter;
mod c_api;

#[derive(Debug)]
struct MonitorContext {
    sender: mpsc::Sender<Packet>,

    #[cfg(feature = "tokio")]
    notify: Option<std::sync::Weak<tokio::sync::Notify>>,
}

type UserContext = *mut RwLock<MonitorContext>;

#[derive(Debug)]
pub struct RealTimeBackend {
    api: c_api::PacketMonitorApi,

    handle: c_api::PacketMonitorHandle,
    session: c_api::PacketMonitorSession,
    stream: c_api::PacketMonitorRealTimeStream,

    receiver: mpsc::Receiver<Packet>,

    context: Box<RwLock<MonitorContext>>,

    loaded: bool,
}

extern "stdcall" fn event_callback(
    _context: *mut c_void, 
    event_info: *const c_api::PacketMonitorStreamEventInfo, 
    event_kind: c_api::PacketMonitorStreamEventKind
) {
    match event_kind {
        c_api::PacketMonitorStreamEventKind::PacketMonitorStreamEventStarted => {
            let info = unsafe { &(*event_info).stream_start_info };
            debug!(
                "Packet monitor stream started with buffer size {} and truncation size {}", 
                info.packet_buffer_size_in_bytes, 
                info.truncation_size
            );
        },
        c_api::PacketMonitorStreamEventKind::PacketMonitorStreamEventStopped => {
            let info = unsafe { &(*event_info).stream_stop_info };
            if info.is_fatal_error {
                error!("Fatal packet monitor stream error with reason: {}", info.reason);
            } else {
                debug!(
                    "Packet monitor stream stopped with reason: {}", 
                    info.reason
                );
            }
        },
        c_api::PacketMonitorStreamEventKind::PacketMonitorStreamEventFatalError => {
            error!("Fatal packet monitor stream event");
        },
        c_api::PacketMonitorStreamEventKind::PacketMonitorStreamEventProcessInfo => {
            let info = unsafe { &(*event_info).stream_process_info };
            if info.is_warning {
                warn!(
                    "Packet monitor stream warning reason: {}, packet length: {}", 
                    info.reason,
                    info.packet_length
                );
            } else {
                error!(
                    "Packet monitor stream error reason: {}, packet length: {}", 
                    info.reason,
                    info.packet_length
                );
            }
        },
    }
}

extern "stdcall" fn data_callback(
    context: *mut c_void,
    data: *const c_api::PacketMonitorStreamDataDescriptor
) {
    let context = unsafe { &mut *(context as UserContext) };

    let descriptor = unsafe { &(*data) };

    let metadata: &c_api::PacketMonitorStreamMetadata = unsafe { 
        &*(descriptor.data.add(descriptor.metadata_offset as usize) as *const c_api::PacketMonitorStreamMetadata) 
    };

    trace!("Packet type: {:?}", metadata.packet_type);

    // TODO: Allow exposing other packet types in the API
    if metadata.packet_type != PacketMonitorPacketType::PktMonPayload_Ethernet as u16 {
        debug!("Packet type is not ethernet, skipping");
        return;
    }

    let packet_payload = unsafe { 
        (descriptor.data as *const u8).add(descriptor.packet_offset as usize) 
    };
    let packet_payload = slice_from_raw_parts(packet_payload, descriptor.packet_length as usize);
    let mut packet_payload_vec = Vec::new();
    packet_payload_vec.extend_from_slice(unsafe { &*packet_payload });

    let packet = Packet { payload: packet_payload_vec };

    let sender = context.read().unwrap().sender.clone();
    sender.send(packet).unwrap();

    #[cfg(feature = "tokio")]
    if let Some(ref notify) = context.read().unwrap().notify {
        if let Some(notify) = notify.upgrade() {
            notify.notify_one();
        }
    }
}

impl RealTimeBackend {
    pub fn new() -> std::io::Result<Self> {
        let api = c_api::PacketMonitorApi::new()?;

        let mut handle = c_api::PacketMonitorHandle::default();
        (api.initialize)(c_api::PACKETMONITOR_API_VERSION, std::ptr::null_mut(), &mut handle).ok()?;
        trace!("Initialized handle {:?}", handle);

        let mut session = c_api::PacketMonitorSession::default();
        (api.create_live_session)(handle, w!("PktMon Rust"), &mut session).ok()?;

        trace!("Created session {:?}", session);

        let (sender, receiver) = mpsc::channel();

        let context_box = Box::new(RwLock::new(MonitorContext { sender, notify: None }));
        let context_ptr = &*context_box as *const _;

        let stream_config = c_api::PacketMonitorRealTimeStreamConfiguration {
            user_context: context_ptr as *mut c_void,
            event_callback: event_callback as *mut _,
            data_callback: data_callback as *mut _,
            buffer_size_multiplier: 5, // Idk if this is a good default
            truncation_size: 9000, // Max value
        };

        let mut stream = c_api::PacketMonitorRealTimeStream::default();
        (api.create_realtime_stream)(
            handle,
            &stream_config, 
            &mut stream
        ).ok()?;

        trace!("Created stream {:?}", stream);

        (api.attach_output_to_session)(session, stream).ok()?;

        Ok(RealTimeBackend {
            api,

            handle,
            session,
            stream,

            context: context_box,

            receiver,

            loaded: true,
        })
    }

    // TODO: Expose this in the API, allow for filtering components
    #[allow(dead_code)]
    fn list_data_sources(&self) -> std::io::Result<Vec<c_api::PacketMonitorDataSourceSpecification>> {
        let mut bytes_needed = 0;

        (self.api.enum_data_sources)(
            self.handle,
            c_api::PacketMonitorDataSourceKind::PacketMonitorDataSourceKindAll,
            false,
            0,
            &mut bytes_needed,
            std::ptr::null_mut()
        ).ok()?;

        let align = std::mem::align_of::<PacketMonitorDataSourceList>();
        let layout = Layout::from_size_align(bytes_needed as usize, align).unwrap();
        let buffer: *mut PacketMonitorDataSourceList = unsafe { std::alloc::alloc_zeroed(layout).cast() };

        trace!("Bytes needed: {}, align: {}", bytes_needed, align);

        (self.api.enum_data_sources)(
            self.handle,
            c_api::PacketMonitorDataSourceKind::PacketMonitorDataSourceKindAll,
            false,
            bytes_needed,
            &mut bytes_needed,
            buffer
        ).ok()?;

        let buf_as_slice = slice_from_raw_parts(buffer as *const u8, bytes_needed as usize);
        let mut vec = Vec::<u8>::new();
        vec.extend_from_slice(unsafe { &*buf_as_slice });
        trace!("Buffer hexdump: {:?}", vec.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(" "));

        let mut result_vec = Vec::<c_api::PacketMonitorDataSourceSpecification>::new();

        unsafe {
            let data_sources = &*buffer;

            trace!("Data sources: {:?}", data_sources);

            for i in 0..data_sources.num_data_sources {
                let data_source = {
                    let ptrptr = data_sources.data_sources.as_ptr();
                    &**(ptrptr.add(i as usize))
                };

                let name = OsString::from_wide(&data_source.name[..data_source.name.iter().position(|&c| c == 0).unwrap_or(data_source.name.len())]);
                let description = OsString::from_wide(&data_source.description[..data_source.description.iter().position(|&c| c == 0).unwrap_or(data_source.description.len())]);

                trace!("Data source: {:?} - {:?} - id: {} - is_present: {}", name, description, data_source.id, data_source.is_present);

                result_vec.push(data_source.clone());
            }
        };

        unsafe { std::alloc::dealloc(buffer.cast(), layout); }

        Ok(result_vec)
    }
}

impl CaptureBackend for RealTimeBackend {
    fn start(&mut self) -> std::io::Result<()> {
        info!("Setting session active");
        (self.api.set_session_active)(self.session, true).ok()?;

        Ok(())
    }

    fn stop(&mut self) -> std::io::Result<()> {
        info!("Setting session inactive");
        (self.api.set_session_active)(self.session, false).ok()?;

        Ok(())
    }

    fn unload(&mut self) -> std::io::Result<()> {
        if self.loaded {
            debug!("Closing stream");
            (self.api.close_realtime_stream)(self.stream);

            debug!("Closing session");
            (self.api.close_session_handle)(self.session);

            debug!("Uninitializing");
            (self.api.uninitialize)(self.handle);

            self.loaded = false;
        }

        Ok(())
    }

    fn add_filter(&mut self, filter: PktMonFilter) -> std::io::Result<()> {
        info!("Adding filter");
        (self.api.add_capture_constraint)(self.session, &filter.into()).ok()?;

        Ok(())
    }

    fn next_packet(&self) -> Result<Packet, mpsc::RecvError> {
        debug!("Receiving packet");
        self.receiver.recv()
    }

    fn next_packet_timeout(&self, timeout: Duration) -> Result<Packet, mpsc::RecvTimeoutError> {
        debug!("Receiving packet with timeout");
        self.receiver.recv_timeout(timeout)
    }

    fn try_next_packet(&self) -> Result<Packet, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }

    #[cfg(feature = "tokio")]
    fn set_notify(&mut self, notify: std::sync::Arc<tokio::sync::Notify>) {
        self.context.write().unwrap().notify = Some(std::sync::Arc::downgrade(&notify));
    }
}

impl Drop for RealTimeBackend {
    fn drop(&mut self) {
        self.unload().unwrap();
    }
}
