#[cfg(feature = "local-scan")]
mod access;
pub mod capabilities;
#[cfg(feature = "local-scan")]
mod deep;
#[cfg(feature = "local-scan")]
mod dlp;
#[cfg(feature = "local-scan")]
mod ebpf;
pub mod file_capabilities;
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
pub mod runtime;
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

// ── NEW SCANNERS (SEC-038/039/040) ──
#[cfg(feature = "local-scan")]
mod confinement;
#[cfg(feature = "local-scan")]
mod ftrace;
#[cfg(feature = "local-scan")]
pub mod kernel_facts;
#[cfg(feature = "local-scan")]
mod kernel_modules;
#[cfg(feature = "local-scan")]
pub mod kernel_taint;
#[cfg(feature = "local-scan")]
pub mod preload;
