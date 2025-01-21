use std::{ffi::c_void, sync::{mpsc::{self, Receiver, Sender}, Arc, RwLock}, thread::{self, JoinHandle}};

use windows::{core::{self as win, GUID, PCWSTR, PSTR}, w, Win32::{Foundation::{GetLastError, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, INVALID_HANDLE_VALUE, NO_ERROR}, System::Diagnostics::Etw::{CloseTrace, ControlTraceA, EnableTraceEx2, OpenTraceA, ProcessTrace, StartTraceA, TdhGetProperty, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_DISABLE_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_FLUSH, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_INDEPENDENT_SESSION_MODE, EVENT_TRACE_LOGFILEA, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID}}};
use crate::util::s_with_len;
use log::{debug, error, trace};

s_with_len!(LOGGER_NAME, LOGGER_NAME_LEN, "PktMon-Consumer");
const SESSION_GUID: GUID = GUID::from_values(0x5b2b901c, 0x294b, 0x4eab, [0x8c, 0xd4, 0x80, 0x39, 0xa6, 0x08, 0x6f, 0x35]);

// wevtutil gp Microsoft-Windows-PktMon
const PKTMON_PROVIDER_GUID: GUID = GUID::from_values(0x4d4f80d9, 0xc8bd, 0x4d73, [0xbb, 0x5b, 0x19, 0xc9, 0x04, 0x02, 0xc5, 0xac]);

#[allow(dead_code)]
enum PktMonKeywords {
    Config    = 0x01,
    Rundown   = 0x02,
    NblParsed = 0x04,
    NblInfo   = 0x08,
    Payload   = 0x10,
}

// We only care about the payload keyword
const DEFAULT_KEYWORDS: u64 = PktMonKeywords::Payload as u64;

#[repr(C)]
struct SessionProperties {
    properties: EVENT_TRACE_PROPERTIES,
    logger_name: [u8; LOGGER_NAME_LEN],
}

impl Default for SessionProperties {
    fn default() -> Self {
        let mut session = Self { 
            properties: EVENT_TRACE_PROPERTIES::default(), 
            logger_name: [0; LOGGER_NAME_LEN], // Value is set by StartTraceA
        };

        unsafe {
            std::ptr::copy(LOGGER_NAME.0, session.logger_name.as_mut_ptr(), LOGGER_NAME_LEN);
        }

        session.properties.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
        session.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        session.properties.Wnode.ClientContext = 1; // QPC clock resolution
        session.properties.Wnode.Guid = SESSION_GUID;

        session.properties.LogFileMode = EVENT_TRACE_INDEPENDENT_SESSION_MODE | EVENT_TRACE_REAL_TIME_MODE;
        session.properties.BufferSize = 64 * 1024; // 64kb
        session.properties.FlushTimer = 1; // 1 second

        session.properties.LoggerNameOffset = std::mem::offset_of!(Self, logger_name) as u32;
        session.properties.LogFileNameOffset = 0; // Do not use a log file since we are using real-time mode

        session
    }
}

#[derive(Default)]
pub struct EtwSession {
    session_properties: SessionProperties,
    control_handle: CONTROLTRACE_HANDLE,

    trace_on: bool,
}

impl EtwSession {
    pub fn new() -> win::Result<Self> {
        let mut session = Self::default();

        unsafe {
            debug!("Closing any orphaned EtwSession...");
            session.close()?; // Ensure any previously orphaned session is closed

            debug!("Starting EtwSession");

            let error = StartTraceA(
                &mut session.control_handle as *mut CONTROLTRACE_HANDLE,
                LOGGER_NAME,
                &mut session.session_properties.properties
            );

            if error != NO_ERROR {
                return Err(error.into());
            }
        }

        debug!("EtwSession started");

        Ok(session)
    }

    pub fn activate(&mut self) -> win::Result<()> {
        debug!("Activating EtwSession...");

        unsafe {
            let error = EnableTraceEx2(
                self.control_handle,
                &PKTMON_PROVIDER_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                DEFAULT_KEYWORDS,
                0,
                0,
                None,
            );

            if error != NO_ERROR {
                return Err(error.into());
            }
        }

        debug!("EtwSession activated");

        self.trace_on = true;
        Ok(())
    }

    pub fn deactivate(&mut self) -> win::Result<()> {
        debug!("Deactivating EtwSession...");

        unsafe {
            let error = EnableTraceEx2(
                self.control_handle,
                &PKTMON_PROVIDER_GUID,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                DEFAULT_KEYWORDS,
                0,
                0,
                None,
            );

            if error != NO_ERROR {
                return Err(error.into());
            }
        }

        debug!("EtwSession deactivated");

        self.trace_on = false;
        Ok(())
    }

    fn close(&mut self) -> win::Result<()> {
        debug!("Closing EtwSession...");

        unsafe {
            // Flush the trace
            let error = ControlTraceA(
                self.control_handle, 
                LOGGER_NAME,
                &mut self.session_properties.properties,
                EVENT_TRACE_CONTROL_FLUSH
            );

            if error != NO_ERROR && error != ERROR_WMI_INSTANCE_NOT_FOUND {
                return Err(error.into());
            }

            // Attempt to stop the trace
            let error = ControlTraceA(
                self.control_handle,
                LOGGER_NAME,
                &mut self.session_properties.properties,
                EVENT_TRACE_CONTROL_STOP
            );

            if error != NO_ERROR && error != ERROR_WMI_INSTANCE_NOT_FOUND {
                return Err(error.into());
            }
        }

        debug!("EtwSession closed");
        Ok(())
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        if self.trace_on {
            if let Err(e) = self.deactivate() {
                error!("Failed to deactivate trace: {:?}", e);
            }
        }

        if let Err(e) = self.close() {
            error!("Failed to close trace: {:?}", e);
        }
    }
}

pub struct Packet {
    pub payload: Vec<u8>,
}

struct ConsumerContext {
    running: bool,

    sender: Sender<Packet>,
}
pub struct EtwConsumer {
    process_handle: PROCESSTRACE_HANDLE,

    context: Arc<Box<RwLock<ConsumerContext>>>,

    thread: Option<JoinHandle<()>>,

    pub receiver: Receiver<Packet>,

    stopped: bool,
}

impl EtwConsumer {
    pub fn new() -> win::Result<Self> {
        let mut trace = EVENT_TRACE_LOGFILEA::default();
        trace.LoggerName = PSTR::from_raw(LOGGER_NAME.0 as *mut u8);
        trace.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

        trace.Anonymous2.EventRecordCallback = Some(Self::event_record_callback);
        trace.BufferCallback = Some(Self::event_buffer_callback);

        let (sender, receiver) = mpsc::channel();

        let mut boxed = Box::new(RwLock::new(ConsumerContext {
            running: true,
            sender,
        }));
        let context_ptr = &mut*boxed as *mut RwLock<ConsumerContext>; // Really yucky

        let mut this = Self {
            process_handle: PROCESSTRACE_HANDLE::default(),
            context: Arc::new(boxed),
            thread: None,
            receiver,
            stopped: false,
        };

        this.context.write().unwrap().running = true;

        unsafe {
            trace.Context = context_ptr as *mut c_void;

            let handle = OpenTraceA(&mut trace);
            if handle.0 == INVALID_HANDLE_VALUE.0 as u64 {
                return Err(GetLastError().into());
            }

            this.process_handle = handle;
        }

        this.thread = Some(thread::spawn(move || {
            unsafe { 
                ProcessTrace(
                    &[this.process_handle],
                    None, 
                    None
                );
                CloseTrace(this.process_handle);
            };
        }));

        debug!("EtwConsumer started");

        Ok(this)
    }

    pub fn stop(&mut self) -> win::Result<()> {
        if self.stopped {
            return Ok(());
        }

        self.stopped = true;

        { // Scope for the lock
            let mut context = self.context.write().unwrap();
            context.running = false;
        }

        // Force the trace to close
        // This is necesary if no events are received, for
        // which ProcessTrace will never return apparently
        // TODO: Only do this if join takes too long
        unsafe {
            CloseTrace(self.process_handle);
        }

        // Join the thread
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }

        Ok(())
    }

    pub extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
        let context = unsafe {
            let context = (*event_record).UserContext;
            &*(context as *mut RwLock<ConsumerContext>)
        };

        unsafe { 
            let record = *event_record;

            // Frame Payload
            if record.EventHeader.EventDescriptor.Id == 160 {
                let original_payload_size = match get_event_property_value_u32(
                    event_record, 
                    w!("LoggedPayloadSize")
                ) {
                    Ok(size) => size,
                    Err(e) => {
                        error!("Failed to get LoggedPayloadSize {:#?}", e);
                        return;
                    }
                };

                let payload = match get_event_property_value_bytes(
                    event_record, 
                    w!("Payload"),
                    original_payload_size
                ) {
                    Ok(payload) => payload,
                    Err(e) => {
                        error!("Failed to get Payload {:#?}", e);
                        return;
                    }
                };

                trace!("Received packet with payload size: {:?}", payload.len());
                match context.read() {
                    Ok(ctx) => {
                        if let Err(e) = ctx.sender.send(Packet { payload }) {
                            error!("Failed to send packet to channel: {:#?}", e);
                        }
                    }
                    Err(e) => error!("Failed to acquire read lock: {:#?}", e),
                }
            }
        }
    }

    pub extern "system" fn event_buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEA) -> u32 {
        let context = unsafe {
            let context = (*logfile).Context;

            // type is *mut c_void
            &*(context as *mut RwLock<ConsumerContext>)
        };

        let context = context.read().unwrap();

        if !context.running {
            return 0;
        }

        1 // Continue
    }
}

impl Drop for EtwConsumer {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            error!("Failed to stop EtwConsumer: {:#?}", e);
        }
    }
}

unsafe fn get_event_property_value_bytes(
    event_record: *mut EVENT_RECORD,
    property_name: PCWSTR,
    property_size: u32,
) -> win::Result<Vec<u8>> {
    let mut buffer = vec![0; property_size as usize];

    let error = TdhGetProperty(
        event_record,
        None,
        &[PROPERTY_DATA_DESCRIPTOR {
            PropertyName: property_name.0 as u64,
            ArrayIndex: 0,
            Reserved: 0,
        }],
        &mut buffer
    );
    
    if error != ERROR_SUCCESS.0 {
        return Err(GetLastError().into());
    }

    Ok(buffer)
}

unsafe fn get_event_property_value_u32(
    event_record: *mut EVENT_RECORD,
    property_name: PCWSTR,
) -> win::Result<u32> {
    let mut bytes = [0; std::mem::size_of::<u32>()];

    let error = TdhGetProperty(
        event_record,
        None,
        &[PROPERTY_DATA_DESCRIPTOR {
            PropertyName: property_name.0 as u64,
            ArrayIndex: 0,
            Reserved: 0,
        }],
        &mut bytes
    );

    if error != ERROR_SUCCESS.0 {
        return Err(GetLastError().into());
    }
    
    Ok(std::mem::transmute(bytes))
}
