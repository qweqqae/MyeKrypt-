use zeroize::Zeroizing;

use crate::error::{Error, Result};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;

#[cfg(target_os = "linux")]
use std::fs;

pub fn get_hwid() -> Result<Zeroizing<String>> {
    sys_hwid()
        .map(Zeroizing::new)
        .ok_or(Error::HardwareId("no stable machine identifier on this system"))
}

#[cfg(target_os = "macos")]
fn sys_hwid() -> Option<String> {
    if let Some(uuid) = run("/usr/sbin/sysctl", &["-n", "hw.uuid"]) {
        let uuid = uuid.trim();
        if !uuid.is_empty() {
            return Some(uuid.to_owned());
        }
    }

    let ioreg = run("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])?;
    for line in ioreg.lines() {
        if !line.contains("IOPlatformUUID") {
            continue;
        }
        let value = line.split('=').nth(1)?.trim().trim_matches('"').trim();
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn sys_hwid() -> Option<String> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(contents) = fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn sys_hwid() -> Option<String> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());

    let powershell = format!(r"{system_root}\System32\WindowsPowerShell\v1.0\powershell.exe");
    if let Some(uuid) = run(
        &powershell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID",
        ],
    ) {
        let uuid = uuid.trim();
        if !uuid.is_empty() {
            return Some(uuid.to_owned());
        }
    }

    let wmic = format!(r"{system_root}\System32\wbem\WMIC.exe");
    let output = run(&wmic, &["csproduct", "get", "uuid"])?;
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && *line != "UUID")
        .map(str::to_owned)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn sys_hwid() -> Option<String> {
    None
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}
