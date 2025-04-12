use log::{debug, trace};
use windows::core as win;
use windows::core::{IntoParam, Param, s};
use windows::Win32::Foundation::{CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, TRUE};
use windows::Win32::Security::SC_HANDLE;
use windows::Win32::Storage::FileSystem::{CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerA, OpenServiceA, StartServiceA,
    SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_START, SERVICE_STATUS, SERVICE_STOP,
};
use windows::Win32::System::IO::DeviceIoControl;

use crate::c_filter::CPktMonFilter;
use crate::filter::PktMonFilter;

#[repr(transparent)]
#[derive(Debug, Clone)]
struct SvcHandle(SC_HANDLE);
impl Drop for SvcHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

impl From<SC_HANDLE> for SvcHandle {
    fn from(handle: SC_HANDLE) -> Self {
        Self(handle)
    }
}

impl IntoParam<SC_HANDLE> for &SvcHandle {
    fn into_param(self) -> Param<SC_HANDLE> {
        Param::Borrowed(self.0)
    }
}

pub struct Driver {
    handle: HANDLE,
}

impl Driver {
    pub fn new() -> win::Result<Self> {
        unsafe {
            trace!("Starting PktMon service...");

            // Open SC Manager
            let h_manager: SvcHandle = OpenSCManagerA(
                None,
                s!("ServicesActive"),
                SC_MANAGER_CONNECT,
            )?.into();
            trace!("Opened SC Manager");

            // Open PktMon service
            // let h_service: SvcHandle = OpenServiceA(
            //     &h_manager,
            //     s!("PktMon"),
            //     SERVICE_START | SERVICE_STOP,
            // )?.into();
            let h_service: SvcHandle = match OpenServiceA(
                &h_manager,
                s!("PktMon"),
                SERVICE_START | SERVICE_STOP,
            ) {
                Ok(handle) => handle.into(),
                Err(e) => {
                    debug!("Failed to open PktMon service: {:?}", e);
                    return Err(e);
                }
            };
            trace!("Opened PktMon service");

            // Start the service
            StartServiceA(&h_service, None);
            debug!("Started PktMon service");

            // Open device handle
            let device_path = s!("\\\\.\\PktMonDev");
            let h_driver = CreateFileA(
                device_path,
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?;

            trace!("Opened PktMon device");
            let driver = Driver { handle: h_driver };

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

    pub fn unload() -> win::Result<()> {
        unsafe {
            debug!("Unloading PktMon service...");

            let h_manager: SvcHandle = OpenSCManagerA(
                None,
                s!("ServicesActive"),
                SC_MANAGER_CONNECT,
            )?.into();

            let h_service: SvcHandle = OpenServiceA(
                &h_manager,
                s!("PktMon"),
                SERVICE_START | SERVICE_STOP,
            )?.into();


            let mut status = SERVICE_STATUS::default();
            ControlService(&h_service, SERVICE_CONTROL_STOP, &mut status);

            debug!("Unloaded PktMon service");

            Ok(())
        }
    }

    pub fn is_running(&self) -> win::Result<bool> {
        unsafe {
            const IOCTL_GET_STATE: u32 = 0x220424;
            let mut bytes_returned: u32 = 0;
            let mut out_buffer: [u8; 0x14] = [0; 0x14];

            let result = DeviceIoControl(
                self.handle,
                IOCTL_GET_STATE,
                None,
                0,
                Some(out_buffer.as_mut_ptr() as *mut _),
                out_buffer.len() as u32,
                Some(&mut bytes_returned),
                None,
            );

            if result == TRUE {
                Ok(out_buffer[4] != 0)
            } else {
                Err(GetLastError().into())
            }
        }
    }

    pub fn start_capture(&self) -> win::Result<()> {
        unsafe {
            debug!("Starting capture...");

            const IOCTL_START: u32 = 0x220404;
            let mut bytes_returned: u32 = 0;

            let mut buffer: [u8; 0x14] = [
                0x14, 0x0, 0x0, 0x0,  // Size
                0x01, 0x0, 0x0, 0x0,  // Components (1 = All)
                0x14, 0x0, 0x0, 0x0,  // Unknown
                0x01, 0x0, 0x0, 0x0,  // Unknown
                0x01, 0x0, 0x00, 0x00 // Unknown
            ];

            let result = DeviceIoControl(
                self.handle,
                IOCTL_START,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            );

            if result == TRUE {
                Ok(())
            } else {
                Err(GetLastError().into())
            }
        }
    }

    pub fn stop_capture(&self) -> win::Result<()> {
        unsafe {
            debug!("Stopping capture...");

            const IOCTL_STOP: u32 = 0x220408;
            let mut bytes_returned: u32 = 0;
            let mut out_buffer: [u8; 0x14] = [0; 0x14];

            let result = DeviceIoControl(
                self.handle,
                IOCTL_STOP,
                None,
                0,
                Some(out_buffer.as_mut_ptr() as *mut _),
                out_buffer.len() as u32,
                Some(&mut bytes_returned),
                None,
            );

            if result == TRUE {
                Ok(())
            } else {
                Err(GetLastError().into())
            }
        }
    }

    pub fn remove_all_filters(&self) -> win::Result<()> {
        unsafe {
            debug!("Removing all filters...");

            const IOCTL_REMOVE_ALL_FILTERS: u32 = 0x220414;
            let mut bytes_returned: u32 = 0;

            let result = DeviceIoControl(
                self.handle,
                IOCTL_REMOVE_ALL_FILTERS,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            );

            if result == TRUE {
                Ok(())
            } else {
                Err(GetLastError().into())
            }
        }
    }

    pub fn add_filter(&self, filter: PktMonFilter) -> win::Result<()> {
        unsafe {
            debug!("Adding filter {:?}", filter);

            const IOCTL_ADD_FILTER: u32 = 0x220410;
            let mut bytes_returned: u32 = 0;

            let filter = CPktMonFilter::from(filter);
            let filter_bytes = filter.as_bytes();

            let result = DeviceIoControl(
                self.handle,
                IOCTL_ADD_FILTER,
                Some(filter_bytes.as_ptr() as *mut _),
                filter_bytes.len() as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            );

            if result == TRUE {
                Ok(())
            } else {
                Err(GetLastError().into())
            }
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
