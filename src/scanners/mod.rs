#[cfg(feature = "local-scan")]
mod access;
pub mod capabilities;
#[cfg(feature = "local-scan")]
mod deep;
#[cfg(feature = "local-scan")]
mod dlp;
#[cfg(feature = "local-scan")]
pub mod docker;
#[cfg(feature = "local-scan")]
mod ebpf;
#[cfg(feature = "local-scan")]
mod file_capabilities;
#[cfg(feature = "local-scan")]
mod fs_inventory;
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
mod provenance;
#[cfg(feature = "local-scan")]
mod reverse_shell;
#[cfg(feature = "local-scan")]
pub mod security;
#[cfg(feature = "local-scan")]
pub mod self_integrity;
#[cfg(feature = "local-scan")]
mod setuid;
#[cfg(feature = "local-scan")]
pub mod storage;
#[cfg(feature = "local-scan")]
mod sudoers;
