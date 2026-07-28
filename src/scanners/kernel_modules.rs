//! Agentless kernel-module integrity via three-source reconciliation (SEC-040).
//! Flags modules present in /sys/module(live) or /proc/kallsyms but scrubbed
//! from /proc/modules — the Diamorphine-class module_list-unlink signature.
//! FP controls (this feeds an exit-3 IoC): built-in modules excluded via
//! missing `initstate`; bpf/ftrace/kernel/vdso/vsyscall/vvar pseudo-modules
//! excluded from kallsyms.
//! Userspace ceiling documented: a rootkit scrubbing all three defeats this.
//! std-only, capped reads, no new crates.

use crate::coverage;
use crate::models::{HiddenModule, KernelModuleInventory};
use crate::safe_io;
use std::collections::BTreeSet;
use std::fs;

const CAP_PROC_MODULES: usize = 4 * 1024 * 1024;
const CAP_KALLSYMS: usize = 32 * 1024 * 1024;

/// Bracketed kallsyms tags that are NOT loadable modules.
const PSEUDO_MODULES: &[&str] = &[
    "bpf",
    "ftrace",
    "kernel",            // built-in
    "vdso",              // userspace helper
    "vsyscall",          // legacy vDSO
    "vvar",              // vDSO data
    "__builtin__ftrace", // kernel synthetic ftrace module (not a loadable module)
];

/// First whitespace token of each /proc/modules line is the module name.
pub(crate) fn parse_proc_modules(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter_map(|l| l.split_ascii_whitespace().next())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Bracketed module names from kallsyms, minus pseudo-modules.
/// Line shape: `ffffffffc0a2e010 t hooked\t[diamorphine]`.
pub(crate) fn parse_kallsyms_modules(content: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for line in content.lines() {
        if let Some(open) = line.rfind('[')
            && let Some(close) = line[open + 1..].find(']')
        {
            let name = line[open + 1..open + 1 + close].trim();
            if !name.is_empty() && !PSEUDO_MODULES.contains(&name) {
                set.insert(name.to_string());
            }
        }
    }
    set
}

/// Names in `sysfs_live ∪ kallsyms` absent from `proc_modules`.
pub(crate) fn reconcile(
    proc_modules: &BTreeSet<String>,
    sysfs_live: &BTreeSet<String>,
    kallsyms: &BTreeSet<String>,
) -> Vec<HiddenModule> {
    let mut out: Vec<HiddenModule> = Vec::new();
    let mut push = |name: &str, source: &str| {
        if proc_modules.contains(name) {
            return;
        }
        match out.iter_mut().find(|h| h.name == name) {
            Some(h) if !h.seen_in.iter().any(|s| s == source) => h.seen_in.push(source.to_string()),
            Some(_) => {}
            None => out.push(HiddenModule {
                name: name.to_string(),
                seen_in: vec![source.to_string()],
            }),
        }
    };
    sysfs_live.iter().for_each(|n| push(n, "sysfs"));
    kallsyms.iter().for_each(|n| push(n, "kallsyms"));
    out
}

/// Live loadable modules from /sys/module/*/initstate == "live".
fn scan_sysfs_live() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(entries) = fs::read_dir("/sys/module") else {
        coverage::record(
            "kernel_modules: /sys/module unreadable — sysfs cross-check skipped".to_string(),
        );
        return set;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        match safe_io::read_file_capped(&format!("/sys/module/{name}/initstate"), 64) {
            Ok((state, _)) if state.trim() == "live" => {
                set.insert(name);
            }
            _ => {} // built-in (no initstate) or transitional — excluded
        }
    }
    set
}

#[cfg(target_os = "linux")]
pub fn gather_kernel_modules() -> KernelModuleInventory {
    let mut proc_modules = match safe_io::read_file_capped("/proc/modules", CAP_PROC_MODULES) {
        Ok((content, truncated)) => {
            if truncated {
                coverage::record(
                    "kernel_modules: /proc/modules truncated — hidden-module check partial"
                        .to_string(),
                );
            }
            parse_proc_modules(&content)
        }
        Err(e) => {
            coverage::record(format!(
                "kernel_modules: /proc/modules unreadable ({}) — hidden-module check UNAVAILABLE",
                e.kind()
            ));
            return KernelModuleInventory::default();
        }
    };

    let sysfs_live = scan_sysfs_live();

    let (kallsyms, kallsyms_checked) =
        match safe_io::read_file_capped("/proc/kallsyms", CAP_KALLSYMS) {
            Ok((content, truncated)) => {
                if truncated {
                    coverage::record(
                        "kernel_modules: /proc/kallsyms truncated — symbols beyond cap not \
                         cross-checked (a hidden module could be missed)"
                            .to_string(),
                    );
                }
                let checked = content.lines().next().is_some();
                if !checked {
                    coverage::record(
                        "kernel_modules: /proc/kallsyms empty — kallsyms cross-check unavailable \
                         (kptr_restrict/CONFIG_KALLSYMS); relying on sysfs only"
                            .to_string(),
                    );
                }
                (parse_kallsyms_modules(&content), checked)
            }
            Err(_) => {
                coverage::record(
                    "kernel_modules: /proc/kallsyms unreadable — kallsyms cross-check skipped"
                        .to_string(),
                );
                (BTreeSet::new(), false)
            }
        };

    // R22-02: second snapshot of /proc/modules after slow reads (kallsyms)
    // to close the TOCTOU window where a module is legitimately loaded between
    // the first /proc/modules read and the kallsyms scan.
    // Union of both snapshots eliminates the false SEC-040 → exit-code-3.
    if let Ok((proc_after_raw, truncated_after)) =
        safe_io::read_file_capped("/proc/modules", CAP_PROC_MODULES)
    {
        if truncated_after {
            coverage::record(
                "kernel_modules: second /proc/modules snapshot truncated — race window partially closed"
                    .to_string(),
            );
        }
        proc_modules.extend(parse_proc_modules(&proc_after_raw));
    } else {
        coverage::record(
            "kernel_modules: second /proc/modules read failed — relying on first snapshot only"
                .to_string(),
        );
    }

    // Guard: if /proc/modules is empty but modules exist in other sources,
    // suppress the hidden check to avoid a flood of false positives.
    if proc_modules.is_empty() && (!sysfs_live.is_empty() || !kallsyms.is_empty()) {
        coverage::record(
            "kernel_modules: /proc/modules empty despite live modules — suppressing hidden check"
                .to_string(),
        );
        return KernelModuleInventory {
            proc_modules: proc_modules.into_iter().collect(),
            sysfs_modules: sysfs_live.into_iter().collect(),
            hidden_candidates: vec![],
            kallsyms_checked,
        };
    }

    let hidden_candidates = reconcile(&proc_modules, &sysfs_live, &kallsyms);

    KernelModuleInventory {
        proc_modules: proc_modules.into_iter().collect(),
        sysfs_modules: sysfs_live.into_iter().collect(),
        hidden_candidates,
        kallsyms_checked,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn gather_kernel_modules() -> KernelModuleInventory {
    KernelModuleInventory::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn diamorphine_hidden_from_proc_is_caught() {
        let proc = set(&["ext4", "nvme"]);
        let sysfs = set(&["ext4", "nvme", "diamorphine"]);
        let kall = set(&["diamorphine"]);
        let hidden = reconcile(&proc, &sysfs, &kall);
        assert_eq!(hidden.len(), 1);
        assert_eq!(hidden[0].name, "diamorphine");
        assert!(hidden[0].seen_in.contains(&"sysfs".to_string()));
        assert!(hidden[0].seen_in.contains(&"kallsyms".to_string()));
    }

    #[test]
    fn clean_host_has_no_hidden_modules() {
        let proc = set(&["ext4", "nvme", "xfs"]);
        let sysfs = set(&["ext4", "nvme", "xfs"]);
        let kall = set(&["ext4", "xfs"]);
        assert!(reconcile(&proc, &sysfs, &kall).is_empty());
    }

    #[test]
    fn kallsyms_pseudo_modules_excluded() {
        let content = "ffffffff81000000 T _text\n\
                       ffffffffc0001000 t bpf_prog\t[bpf]\n\
                       ffffffffc0002000 t ftrace_tramp\t[ftrace]\n\
                       ffffffffc0002000 t kernel_func\t[kernel]\n\
                       ffffffffc0002000 t vdso_func\t[vdso]\n\
                       ffffffffc0002000 t vsyscall_func\t[vsyscall]\n\
                       ffffffffc0002000 t vvar_func\t[vvar]\n\
                       ffffffffc0003000 t real\t[e1000]";
        let names = parse_kallsyms_modules(content);
        assert!(names.contains("e1000"));
        assert!(!names.contains("bpf"));
        assert!(!names.contains("ftrace"));
        assert!(!names.contains("kernel"));
        assert!(!names.contains("vdso"));
        assert!(!names.contains("vsyscall"));
        assert!(!names.contains("vvar"));
    }

    #[test]
    fn proc_modules_name_is_first_token() {
        let content = "diamorphine 16384 0 - Live 0xffffffffc0a2e000 (OE)\n\
                       ext4 987136 3 - Live 0x0000000000000000";
        let names = parse_proc_modules(content);
        assert!(names.contains("diamorphine") && names.contains("ext4"));
    }

    // R22-02 regression tests

    #[test]
    fn racing_insmod_between_reads_is_not_flagged() {
        // Module absent in first /proc/modules snapshot,
        // appears in second snapshot + sysfs/kallsyms — legitimate load, not rootkit.
        let proc_before = set(&["ext4", "nvme"]);
        let proc_after = set(&["ext4", "nvme", "e1000e"]);
        let sysfs = set(&["ext4", "nvme", "e1000e"]);
        let kall = set(&["e1000e"]);

        let mut proc_union = proc_before;
        proc_union.extend(proc_after);
        assert!(
            reconcile(&proc_union, &sysfs, &kall).is_empty(),
            "module loaded during scan is a race, not Diamorphine"
        );
    }

    #[test]
    fn diamorphine_absent_from_both_reads_still_caught() {
        // Real hidden module stays invisible across both /proc/modules snapshots.
        let mut proc_union: BTreeSet<String> = set(&["ext4"]);
        proc_union.extend(set(&["ext4"])); // second read also missing diamorphine
        let sysfs = set(&["ext4", "diamorphine"]);
        let kall = set(&["diamorphine"]);
        let hidden = reconcile(&proc_union, &sysfs, &kall);
        assert_eq!(hidden.len(), 1);
        assert_eq!(hidden[0].name, "diamorphine");
    }
}
