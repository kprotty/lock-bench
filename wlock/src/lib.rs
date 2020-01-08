#![no_std]

#[cfg(any(windows, target_os = "linux"))]
mod futex;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(all(unix, not(target_os = "linux")))]
mod posix;
#[cfg(all(unix, not(target_os = "linux")))]
pub use posix::*;
