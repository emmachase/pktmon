use std::{ffi::c_void, mem::transmute};

use windows::Win32::Foundation::{GetLastError, HMODULE};
use windows::Win32::System::LibraryLoader::FreeLibrary;
use windows::core as win;
use windows::{
    Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA},
    core::{HRESULT, PCWSTR},
    s,
};

use crate::ctypes::{CIPAddr, CMacAddr};

use super::c_filter::PacketMonitorProtocolConstraint;

// TODO: Use bind-gen bindings

#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct SendHandle(pub *mut c_void);
unsafe impl Send for SendHandle {}
impl Default for SendHandle {
    fn default() -> Self {
        Self(std::ptr::null_mut())
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PacketMonitorHandle(pub SendHandle);

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PacketMonitorSession(SendHandle);

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PacketMonitorRealTimeStream(pub SendHandle);

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketMonitorStreamStartInfoOut {
    pub packet_buffer_size_in_bytes: u32,
    pub truncation_size: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketMonitorStreamStopInfoOut {
    pub is_fatal_error: bool,
    pub reason: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketMonitorStreamProcessInfoOut {
    pub is_warning: bool,
    pub reason: u32,
    pub packet_length: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PacketMonitorStreamEventInfo {
    pub stream_start_info: PacketMonitorStreamStartInfoOut,
    pub stream_stop_info: PacketMonitorStreamStopInfoOut,
    pub stream_process_info: PacketMonitorStreamProcessInfoOut,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
pub enum PacketMonitorStreamEventKind {
    PacketMonitorStreamEventStarted,
    PacketMonitorStreamEventStopped,
    PacketMonitorStreamEventFatalError,
    PacketMonitorStreamEventProcessInfo,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[allow(dead_code, non_camel_case_types)]
pub enum PacketMonitorPacketType {
    PktMonPayload_Unknown,
    PktMonPayload_Ethernet,
    PktMonPayload_WiFi,
    PktMonPayload_IP,
    PktMonPayload_HTTP,
    PktMonPayload_TCP,
    PktMonPayload_UDP,
    PktMonPayload_ARP,
    PktMonPayload_ICMP,
    PktMonPayload_ESP,
    PktMonPayload_AH,
    PktMonPayload_L4Payload,
}

impl TryFrom<u16> for PacketMonitorPacketType {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::PktMonPayload_Unknown as u16 => Ok(Self::PktMonPayload_Unknown),
            x if x == Self::PktMonPayload_Ethernet as u16 => Ok(Self::PktMonPayload_Ethernet),
            x if x == Self::PktMonPayload_WiFi as u16 => Ok(Self::PktMonPayload_WiFi),
            x if x == Self::PktMonPayload_IP as u16 => Ok(Self::PktMonPayload_IP),
            x if x == Self::PktMonPayload_HTTP as u16 => Ok(Self::PktMonPayload_HTTP),
            x if x == Self::PktMonPayload_TCP as u16 => Ok(Self::PktMonPayload_TCP),
            x if x == Self::PktMonPayload_UDP as u16 => Ok(Self::PktMonPayload_UDP),
            x if x == Self::PktMonPayload_ARP as u16 => Ok(Self::PktMonPayload_ARP),
            x if x == Self::PktMonPayload_ICMP as u16 => Ok(Self::PktMonPayload_ICMP),
            x if x == Self::PktMonPayload_ESP as u16 => Ok(Self::PktMonPayload_ESP),
            x if x == Self::PktMonPayload_AH as u16 => Ok(Self::PktMonPayload_AH),
            x if x == Self::PktMonPayload_L4Payload as u16 => Ok(Self::PktMonPayload_L4Payload),
            _ => Err(()),
        }
    }
}

pub type PacketMonitorStreamEventCallback = extern "stdcall" fn(
    context: *mut c_void,
    event_info: *const PacketMonitorStreamEventInfo,
    event_kind: PacketMonitorStreamEventKind,
);

pub type PacketMonitorStreamDataCallback =
    extern "stdcall" fn(context: *mut c_void, data: *const PacketMonitorStreamDataDescriptor);

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketMonitorStreamDataDescriptor {
    pub data: *const c_void,
    pub data_size: u32,

    pub metadata_offset: u32,
    pub packet_offset: u32,
    pub packet_length: u32,
    pub missed_packet_write_count: u32,
    pub missed_packet_read_count: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketMonitorStreamMetadata {
    pub pkt_group_id: u64,
    pub pkt_count: u16,
    pub appearance_count: u16,
    pub direction_name: u16,
    pub packet_type: u16,
    pub component_id: u16,
    pub edge_id: u16,
    pub reserved: u16,
    pub drop_reason: u32,
    pub drop_location: u32,
    pub processor: u16,
    pub timestamp: i64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketMonitorRealTimeStreamConfiguration {
    pub user_context: *mut c_void,
    pub event_callback: *mut PacketMonitorStreamEventCallback,
    pub data_callback: *mut PacketMonitorStreamDataCallback,
    pub buffer_size_multiplier: u16,
    pub truncation_size: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
pub enum PacketMonitorDataSourceKind {
    PacketMonitorDataSourceKindAll,
    PacketMonitorDataSourceKindNetworkInterface,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketMonitorDataSourceSpecification {
    pub kind: PacketMonitorDataSourceKind,
    pub name: [u16; 64],
    pub description: [u16; 128],

    pub id: u32,
    pub secondary_id: u32,

    pub parent_id: u32,

    pub is_present: u32,
    pub detail: PacketMonitorDataSourceDetail,
}

#[allow(dead_code)]
impl PacketMonitorDataSourceSpecification {
    pub fn name(&self) -> String {
        let name = self
            .name
            .iter()
            .take_while(|&&c| c != 0)
            .copied()
            .collect::<Vec<u16>>();
        String::from_utf16_lossy(&name)
    }

    pub fn description(&self) -> String {
        let description = self
            .description
            .iter()
            .take_while(|&&c| c != 0)
            .copied()
            .collect::<Vec<u16>>();
        String::from_utf16_lossy(&description)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PacketMonitorDataSourceDetail {
    pub guid: u32,
    pub ip_address: CIPAddr,
    pub mac_address: CMacAddr,
}

impl std::fmt::Debug for PacketMonitorDataSourceDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PacketMonitorDataSourceDetail {{ idk lol }}")
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketMonitorDataSourceList {
    pub num_data_sources: u32,
    pub data_sources: [*const PacketMonitorDataSourceSpecification; 1],
}

pub const PACKETMONITOR_API_VERSION: u32 = 0x00010000;

#[derive(Debug)]
#[allow(dead_code)]
pub struct PacketMonitorApi {
    module: HMODULE,

    pub initialize: extern "stdcall" fn(
        api_version: u32,
        reserved: *mut c_void,
        handle: *mut PacketMonitorHandle,
    ) -> HRESULT,
    pub uninitialize: extern "stdcall" fn(handle: PacketMonitorHandle),
    pub create_live_session: extern "stdcall" fn(
        handle: PacketMonitorHandle,
        name: PCWSTR,
        session: *mut PacketMonitorSession,
    ) -> HRESULT,
    pub set_session_active:
        extern "stdcall" fn(session: PacketMonitorSession, active: bool) -> HRESULT,
    pub create_realtime_stream: extern "stdcall" fn(
        handle: PacketMonitorHandle,
        configuration: *const PacketMonitorRealTimeStreamConfiguration,
        realtime_stream: *mut PacketMonitorRealTimeStream,
    ) -> HRESULT,
    pub attach_output_to_session: extern "stdcall" fn(
        session: PacketMonitorSession,
        output_handle: PacketMonitorRealTimeStream,
    ) -> HRESULT,
    pub close_session_handle: extern "stdcall" fn(session: PacketMonitorSession),
    pub close_realtime_stream: extern "stdcall" fn(realtime_stream: PacketMonitorRealTimeStream),
    pub add_capture_constraint: extern "stdcall" fn(
        session: PacketMonitorSession,
        capture_constraint: *const PacketMonitorProtocolConstraint,
    ) -> HRESULT,
    pub enum_data_sources: extern "stdcall" fn(
        handle: PacketMonitorHandle,
        source_kind: PacketMonitorDataSourceKind,
        show_hidden: bool,
        buffer_capacity: u32,
        bytes_needed: *mut u32,
        data_source_list: *mut PacketMonitorDataSourceList,
    ) -> HRESULT,
    pub add_single_data_source_to_session: extern "stdcall" fn(
        session: PacketMonitorSession,
        data_source: *const PacketMonitorDataSourceSpecification,
    ) -> HRESULT,
}

impl PacketMonitorApi {
    pub fn new() -> win::Result<Self> {
        unsafe {
            let module = LoadLibraryA(s!("PktMonApi.dll"))?;

            macro_rules! get_proc_address {
                ($name:expr) => {
                    transmute(
                        GetProcAddress(module, s!($name))
                            .ok_or_else(|| win::Error::from(GetLastError()))?,
                    )
                };
            }

            Ok(PacketMonitorApi {
                module,

                initialize: get_proc_address!("PacketMonitorInitialize"),
                uninitialize: get_proc_address!("PacketMonitorUninitialize"),
                create_live_session: get_proc_address!("PacketMonitorCreateLiveSession"),
                set_session_active: get_proc_address!("PacketMonitorSetSessionActive"),
                create_realtime_stream: get_proc_address!("PacketMonitorCreateRealtimeStream"),
                attach_output_to_session: get_proc_address!("PacketMonitorAttachOutputToSession"),
                close_session_handle: get_proc_address!("PacketMonitorCloseSessionHandle"),
                close_realtime_stream: get_proc_address!("PacketMonitorCloseRealtimeStream"),
                add_capture_constraint: get_proc_address!("PacketMonitorAddCaptureConstraint"),
                enum_data_sources: get_proc_address!("PacketMonitorEnumDataSources"),
                add_single_data_source_to_session: get_proc_address!(
                    "PacketMonitorAddSingleDataSourceToSession"
                ),
            })
        }
    }
}

impl Drop for PacketMonitorApi {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}
