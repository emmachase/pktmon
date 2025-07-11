use std::ffi::c_void;
use std::mem::transmute;

use log::{debug, trace};
use windows::Win32::Foundation::{GetLastError, HMODULE, NO_ERROR, WIN32_ERROR};
use windows::Win32::System::LibraryLoader::{FreeLibrary, GetProcAddress, LoadLibraryA};
use windows::core as win;
use windows::core::s;

use crate::filter::PktMonFilter;
use crate::legacy::c_filter::CPktMonLegacyFilter;

pub struct Driver {
    api: PktMonApi,
}

type CPktMonStatus = [u8; 0x103C];

#[repr(C)]
#[derive(Debug, Clone)]
struct CPktMonStart {
    capture_type: u32, // 1 = All Packets
    _unknown1: u32,
    mode: u32,            // 1 = All, 2 = NICs, 3 = Component List
    component_count: u16, // Should be zero if mode is not 3
    _unknown2: u16,
    component_list_ptr: *mut c_void,
    _unknown3: u16,
}

impl CPktMonStart {
    fn new() -> Self {
        Self {
            capture_type: 1,
            _unknown1: 0,
            mode: 1,
            component_count: 0,
            _unknown2: 0,
            component_list_ptr: std::ptr::null_mut(),
            _unknown3: 0,
        }
    }
}

struct PktMonApi {
    module: HMODULE,

    add_filter: extern "C" fn(*const CPktMonLegacyFilter) -> WIN32_ERROR,
    remove_all_filters: extern "C" fn() -> WIN32_ERROR,
    start_capture: extern "C" fn(*const CPktMonStart, *mut c_void) -> WIN32_ERROR,
    stop_capture: extern "C" fn(*mut CPktMonStatus) -> WIN32_ERROR,
    get_status: extern "C" fn(*mut CPktMonStatus) -> WIN32_ERROR,
    unload: extern "C" fn() -> WIN32_ERROR,
}

impl Driver {
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

            let api = PktMonApi {
                module,

                add_filter: get_proc_address!("PktmonAddFilter"),
                remove_all_filters: get_proc_address!("PktmonRemoveAllFilters"),
                start_capture: get_proc_address!("PktmonStart"),
                stop_capture: get_proc_address!("PktmonStop"),
                get_status: get_proc_address!("PktmonGetStatus"),
                unload: get_proc_address!("PktmonUnload"),
            };

            trace!("Opened PktMon device");
            let driver = Driver { api };

            // If the driver is already running, stop it
            if driver.is_running()? {
                debug!("Driver is already running, stopping it...");
                driver.stop_capture()?;
            }

            // Clear all filters before handing off the driver to ensure we have a clean state
            driver.remove_all_filters()?;

            Ok(driver)
        }
    }

    pub fn unload(&self) -> win::Result<()> {
        debug!("Unloading PktMon service...");

        let err = (self.api.unload)();
        if err != NO_ERROR {
            return Err(err.into());
        }

        debug!("Unloaded PktMon service");

        Ok(())
    }

    pub fn is_running(&self) -> win::Result<bool> {
        let mut status = [0; 0x103C];

        let err = (self.api.get_status)(&mut status);
        if err != NO_ERROR {
            return Err(err.into());
        }

        Ok(status[0] != 0)
    }

    pub fn start_capture(&self) -> win::Result<()> {
        debug!("Starting capture...");

        let err = (self.api.start_capture)(&mut CPktMonStart::new(), std::ptr::null_mut());
        if err != NO_ERROR {
            return Err(err.into());
        }

        Ok(())
    }

    pub fn stop_capture(&self) -> win::Result<()> {
        debug!("Stopping capture...");

        let err = (self.api.stop_capture)(&mut [0; 0x103C]);
        if err != NO_ERROR {
            return Err(err.into());
        }

        Ok(())
    }

    pub fn remove_all_filters(&self) -> win::Result<()> {
        debug!("Removing all filters...");

        let err = (self.api.remove_all_filters)();
        if err != NO_ERROR {
            return Err(err.into());
        }

        Ok(())
    }

    pub fn add_filter(&self, filter: PktMonFilter) -> win::Result<()> {
        debug!("Adding filter {:?}", filter);

        let err = (self.api.add_filter)(&filter.into());
        if err != NO_ERROR {
            return Err(err.into());
        }

        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.api.module);
        }
    }
}
