use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::w;

pub fn enable_debug_privilege() -> Result<()> {
    let mut token: HANDLE = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .context("OpenProcessToken failed")?;
    }

    let mut luid = LUID::default();
    unsafe {
        LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid)
            .context("LookupPrivilegeValueW failed")?;
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: TOKEN_PRIVILEGES_ATTRIBUTES(SE_PRIVILEGE_ENABLED.0),
        }],
    };

    unsafe {
        AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)
            .context("AdjustTokenPrivileges failed")?;
        let _ = CloseHandle(token);
    }

    Ok(())
}
