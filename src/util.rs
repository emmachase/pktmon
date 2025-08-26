use std::sync::{Mutex, Once};
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Console::{
    CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, SetConsoleCtrlHandler,
};

macro_rules! s_with_len {
    ($i:ident, $i_len:ident, $s:literal) => {
        const $i: windows::core::PCSTR =
            windows::core::PCSTR::from_raw(::std::concat!($s, '\0').as_ptr());
        const $i_len: usize = $s.len() + 1;
    };
}

pub(crate) use s_with_len;

static SHUTDOWN_HOOK: Once = Once::new();
static SHUTDOWN_CALLBACK: Mutex<Option<Box<dyn FnOnce() + Send + 'static>>> = Mutex::new(None);

unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            if let Some(callback) = SHUTDOWN_CALLBACK
                .try_lock()
                .ok()
                .map(|mut lock| lock.take())
                .flatten()
            {
                callback();
            }
        }
        _ => {}
    }

    BOOL::from(false) // Allow other handlers to process the signal
}

pub fn install_shutdown_hook(hook: impl FnOnce() + Send + 'static) {
    SHUTDOWN_HOOK.call_once(|| unsafe {
        *SHUTDOWN_CALLBACK.lock().unwrap() = Some(Box::new(hook));
        SetConsoleCtrlHandler(Some(console_ctrl_handler), true);
    });
}
