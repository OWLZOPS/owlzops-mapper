#[cfg(feature = "local-scan")]
mod access;
pub mod capabilities;                // needed by scoring & ui on all platforms
#[cfg(feature = "local-scan")]
mod deep;
#[cfg(feature = "local-scan")]
mod dlp;
#[cfg(feature = "local-scan")]
pub mod docker;
#[cfg(feature = "local-scan")]
mod ghost_pid;
#[cfg(feature = "local-scan")]
pub mod host;
#[cfg(feature = "local-scan")]
mod library_injection;
#[cfg(feature = "local-scan")]
mod mounts;
#[cfg(feature = "local-scan")]
pub mod network;
#[cfg(feature = "local-scan")]
pub mod packages;
#[cfg(feature = "local-scan")]
mod proc_net;
#[cfg(feature = "local-scan")]
mod reverse_shell;
pub mod security;                    // needed by scoring & ui on all platforms
#[cfg(feature = "local-scan")]
pub mod self_integrity;
#[cfg(feature = "local-scan")]
pub mod storage;