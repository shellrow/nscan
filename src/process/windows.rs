use std::io::Error;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

pub fn privileged() -> bool {
    _is_elevated().unwrap_or(false)
}

fn _is_elevated() -> Result<bool, Error> {
    let token = QueryAccessToken::from_current_process()?;
    token.is_elevated()
}

struct QueryAccessToken(HANDLE);

impl QueryAccessToken {
    fn from_current_process() -> Result<Self, Error> {
        unsafe {
            let mut handle = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) != 0 {
                Ok(Self(handle))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    fn is_elevated(&self) -> Result<bool, Error> {
        unsafe {
            let mut elevation: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
            let mut ret_size = size;
            if GetTokenInformation(
                self.0,
                TokenElevation,
                &mut elevation as *const _ as *mut _,
                size,
                &mut ret_size,
            ) != 0
            {
                Ok(elevation.TokenIsElevated != 0)
            } else {
                Err(Error::last_os_error())
            }
        }
    }
}

impl Drop for QueryAccessToken {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
