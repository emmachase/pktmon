use std::ffi::c_void;
use std::mem::transmute;

use log::{debug, trace};
use windows::core as win;
use windows::core::s;
use windows::Win32::Foundation::{NO_ERROR, WIN32_ERROR};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

use crate::legacy::c_filter::CPktMonUserFilter;
use crate::filter::PktMonFilter;

pub struct Driver {
    api: PktMonApi,
}

type CPktMonStatus = [u8; 0x103C];

#[repr(C)]
#[derive(Debug, Clone)]
struct CPktMonStart {
    capture_type: u32, // 1 = All Packets
    _unknown1: u32,
    mode: u32, // 1 = All, 2 = NICs, 3 = Component List
    component_count: u16, // Should be zero if mode is not 3
    _unknown2: u16,
    component_list_ptr: *mut c_void,
    _unknown3: u16,
}

impl CPktMonStart {
    fn new() -> Self {
        Self { capture_type: 1, _unknown1: 0, mode: 1, component_count: 0, _unknown2: 0, component_list_ptr: std::ptr::null_mut(), _unknown3: 0 }
    }
}

struct PktMonApi {
    add_filter: extern "C" fn(*const CPktMonUserFilter) -> WIN32_ERROR,
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

            let api = PktMonApi {
                add_filter: transmute(GetProcAddress(module, s!("PktmonAddFilter")).unwrap()),
                remove_all_filters: transmute(GetProcAddress(module, s!("PktmonRemoveAllFilters")).unwrap()),
                start_capture: transmute(GetProcAddress(module, s!("PktmonStart")).unwrap()),
                stop_capture: transmute(GetProcAddress(module, s!("PktmonStop")).unwrap()),
                get_status: transmute(GetProcAddress(module, s!("PktmonGetStatus")).unwrap()),
                unload: transmute(GetProcAddress(module, s!("PktmonUnload")).unwrap()),
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
