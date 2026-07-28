//! Agentless ftrace/kprobe hook-surface audit (SEC-041).
//!
//! ftrace rootkits attach an ftrace_ops to syscall-entry functions and rewrite
//! regs->ip in the callback. We read tracefs and flag syscall functions that are
//! ftrace-hooked but have NO legitimate source. The whole game is ATTRIBUTION —
//! BPF fentry (Falco/Tetragon), kprobes, livepatch and a live function tracer all
//! populate enabled_functions legitimately and must be filtered out.
//!
//! Userspace ceiling (documented): under kptr_restrict the callback symbol is
//! hidden, so a legit BPF/kprobe source cannot be ruled out → such hooks are
//! reported as informational; the weighted signal then comes from drift (a NEW
//! hooked syscall between snapshots). std-only, capped reads, no new crates.

use crate::coverage;
use crate::models::{FtraceHook, FtraceHookInventory, KprobeEntry};
use crate::safe_io;
use std::fs;
use std::path::Path;

const CAP_ENABLED_FUNCTIONS: usize = 4 * 1024 * 1024;
const CAP_KPROBE_EVENTS: usize = 256 * 1024;

/// Syscall-entry wrapper prefixes (x86_64 primary; others for portability).
const SYSCALL_PREFIXES: &[&str] = &[
    "__x64_sys_",
    "__ia32_sys_",
    "__arm64_sys_",
    "__se_sys_",
    "__do_sys_",
];

pub(crate) fn is_syscall_fn(name: &str) -> bool {
    SYSCALL_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Where the ftrace_ops callback for a hooked function lives.
#[derive(Debug, PartialEq)]
pub(crate) enum HookSource {
    Bpf,
    Kprobe,
    Livepatch,
    KernelBuiltin,
    Module(String),
    Unresolved,
}

/// Classify the attribution tail of an enabled_functions line (flags + callback).
pub(crate) fn classify_hook(attribution: &str) -> HookSource {
    let a = attribution;
    if a.contains("bpf") {
        return HookSource::Bpf;
    }
    if a.contains("klp_") || a.contains("livepatch") {
        return HookSource::Livepatch;
    }
    if a.contains("kprobe") {
        return HookSource::Kprobe;
    }
    if let Some(open) = a.rfind('[')
        && let Some(close) = a[open + 1..].find(']')
    {
        return HookSource::Module(a[open + 1..open + 1 + close].to_string());
    }
    // No resolvable callback (kptr_restrict zeroes %pS) → cannot attribute.
    if !a.contains("->") || a.contains("0x0000000000000000") {
        return HookSource::Unresolved;
    }
    HookSource::KernelBuiltin
}

/// Parse enabled_functions into (function, ops_count, attribution_tail).
/// Line: `__x64_sys_getdents64 (1) R I ->bpf_trampoline_...`
pub(crate) fn parse_enabled_functions(content: &str) -> Vec<(String, u32, String)> {
    content
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let func = it.next()?.to_string();
            let count = it
                .next()
                .and_then(|t| t.strip_prefix('(').and_then(|t| t.strip_suffix(')')))
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let attribution = it.collect::<Vec<_>>().join(" ");
            Some((func, count, attribution))
        })
        .collect()
}

/// Parse kprobe_events: `p:group/name symbol[+off]` / `r[N]:group/name symbol`.
pub(crate) fn parse_kprobe_events(content: &str) -> Vec<KprobeEntry> {
    content
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let head = it.next()?;
            let kind = head.chars().next()?;
            if kind != 'p' && kind != 'r' {
                return None;
            }
            let group_name = head
                .split_once(':')
                .map(|(_, g)| g.to_string())
                .unwrap_or_default();
            let symbol = it.next()?.split(['+', ':']).next()?.to_string();
            Some(KprobeEntry {
                kind,
                group_name,
                symbol,
            })
        })
        .collect()
}

fn tracefs_root() -> Option<&'static str> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .find(|r| Path::new(&format!("{r}/enabled_functions")).exists())
}

fn function_tracer_active(root: &str) -> bool {
    let active = |path: String| {
        safe_io::read_file_capped(&path, 256)
            .map(|(s, _)| {
                let t = s.trim();
                !t.is_empty() && t != "nop"
            })
            .unwrap_or(false)
    };
    if active(format!("{root}/current_tracer")) {
        return true;
    }
    if let Ok(entries) = fs::read_dir(format!("{root}/instances")) {
        for e in entries.flatten() {
            if active(format!("{}/current_tracer", e.path().display())) {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
pub fn gather_ftrace_hooks() -> FtraceHookInventory {
    let mut inv = FtraceHookInventory::default();

    let Some(root) = tracefs_root() else {
        coverage::record(
            "ftrace: tracefs not mounted/readable — syscall-hook check unavailable".to_string(),
        );
        return inv;
    };
    inv.tracefs_available = true;
    inv.live_tracer_active = function_tracer_active(root);

    if let Ok((kp, _)) =
        safe_io::read_file_capped(&format!("{root}/kprobe_events"), CAP_KPROBE_EVENTS)
    {
        inv.syscall_kprobes = parse_kprobe_events(&kp)
            .into_iter()
            .filter(|k| is_syscall_fn(&k.symbol))
            .collect();
    }

    let (content, truncated) = match safe_io::read_file_capped(
        &format!("{root}/enabled_functions"),
        CAP_ENABLED_FUNCTIONS,
    ) {
        Ok(v) => v,
        Err(e) => {
            coverage::record(format!(
                "ftrace: {root}/enabled_functions unreadable ({}) — syscall-hook check unavailable",
                e.kind()
            ));
            return inv;
        }
    };
    if truncated {
        coverage::record(
            "ftrace: enabled_functions truncated — hook set may be partial".to_string(),
        );
    }

    for (func, count, attribution) in parse_enabled_functions(&content) {
        if !is_syscall_fn(&func) {
            continue;
        }
        if inv.live_tracer_active {
            inv.attributed_hook_count += 1;
            continue;
        }
        match classify_hook(&attribution) {
            HookSource::Bpf
            | HookSource::Kprobe
            | HookSource::Livepatch
            | HookSource::KernelBuiltin => inv.attributed_hook_count += 1,
            HookSource::Module(m) => inv.unattributed_syscall_hooks.push(FtraceHook {
                function: func,
                ops_count: count,
                callback: format!("module:{m}"),
            }),
            HookSource::Unresolved => {
                inv.attribution_degraded = true;
                inv.unattributed_syscall_hooks.push(FtraceHook {
                    function: func,
                    ops_count: count,
                    callback: "unresolved".to_string(),
                });
            }
        }
    }

    if inv.live_tracer_active && inv.attributed_hook_count > 0 {
        coverage::record(
            "ftrace: live function tracer active — syscall-hook attribution suppressed \
             (cannot distinguish a rootkit from active tracing)"
                .to_string(),
        );
    }
    inv
}

#[cfg(not(target_os = "linux"))]
pub fn gather_ftrace_hooks() -> FtraceHookInventory {
    FtraceHookInventory::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_syscall_entries() {
        assert!(is_syscall_fn("__x64_sys_getdents64"));
        assert!(is_syscall_fn("__do_sys_kill"));
        assert!(!is_syscall_fn("vfs_read"));
        assert!(!is_syscall_fn("bpf_trampoline_1234"));
    }

    #[test]
    fn attribution_distinguishes_sources() {
        assert_eq!(classify_hook("R I ->bpf_trampoline_6442"), HookSource::Bpf);
        assert_eq!(classify_hook("->klp_ftrace_handler"), HookSource::Livepatch);
        assert_eq!(classify_hook("->kprobe_ftrace_handler"), HookSource::Kprobe);
        assert_eq!(
            classify_hook("R I ->hook_getdents64 [diamorphine]"),
            HookSource::Module("diamorphine".to_string())
        );
        assert_eq!(classify_hook("(1)"), HookSource::Unresolved); // no callback
        assert_eq!(
            classify_hook("->0x0000000000000000"),
            HookSource::Unresolved
        ); // kptr_restrict
    }

    #[test]
    fn parses_enabled_functions_line() {
        let c = "__x64_sys_getdents64 (1) R I ->hook [rootkit]\nvfs_read (2)";
        let v = parse_enabled_functions(c);
        assert_eq!(v[0].0, "__x64_sys_getdents64");
        assert_eq!(v[0].1, 1);
        assert!(v[0].2.contains("[rootkit]"));
    }

    #[test]
    fn parses_kprobe_events() {
        let c = "p:kprobes/myprobe __x64_sys_openat\nr10:grp/ret vfs_read+0x0";
        let k = parse_kprobe_events(c);
        assert_eq!(k[0].kind, 'p');
        assert_eq!(k[0].symbol, "__x64_sys_openat");
        assert_eq!(k[1].kind, 'r');
        assert_eq!(k[1].symbol, "vfs_read");
    }
}
