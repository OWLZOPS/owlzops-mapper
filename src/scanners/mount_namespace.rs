use std::fs;
use std::path::Path;

use crate::coverage;
use crate::models::MountNamespaceAnomaly;
use crate::safe_io;

const MAX_PIDS: usize = 4096;

fn mnt_ns_inode(proc_root: &Path, pid: u32) -> std::io::Result<String> {
    fs::read_link(proc_root.join(format!("{pid}/ns/mnt"))).map(|p| p.to_string_lossy().into_owned())
}

/// The systemd unit or scope owning this pid, taken from its cgroup path.
/// cgroup v2 line: "0::/system.slice/nginx.service".
///
/// R33-10: on hybrid / cgroup v1 hosts the same pid appears once per
/// controller hierarchy, each with its own path. A delegated `pids` or
/// `cpu` tree can lead with a path that contains a `.scope` suffix — the
/// systemd controller (`name=systemd` on v1, `0::` on v2) carries the
/// authoritative unit. Prefer it; fall back to the first path that
/// matches a unit suffix if the systemd hierarchy is not present.
fn systemd_unit(proc_root: &Path, pid: u32) -> Option<String> {
    let p = proc_root.join(format!("{pid}/cgroup"));
    let (cgroup, _) = safe_io::read_procfs_capped(&p.to_string_lossy(), 8192).ok()?;

    fn find_unit(path: &str) -> Option<String> {
        path.rsplit('/')
            .find(|c| c.ends_with(".service") || c.ends_with(".scope"))
            .map(str::to_string)
    }

    let mut fallback: Option<String> = None;
    for line in cgroup.lines() {
        // Format: <hierarchy-id>:<controllers>:<path>.
        // v2: "0::/path" (empty controller list).
        // v1: "1:name=systemd:/path", "12:pids:/path".
        let Some((_, rest)) = line.split_once(':') else {
            continue;
        };
        let Some((controllers, path)) = rest.split_once(':') else {
            continue;
        };
        let path = path.trim();
        if (controllers.is_empty() || controllers == "name=systemd")
            && let Some(u) = find_unit(path)
        {
            return Some(u);
        }
        if fallback.is_none() {
            fallback = find_unit(path);
        }
    }
    fallback
}

pub fn scan_mount_namespace_anomalies() -> Vec<MountNamespaceAnomaly> {
    scan_mount_namespace_anomalies_from(Path::new("/proc"))
}

/// R33-02: no container-pid filter. A container's init is attributed by
/// `mnt_ns` in `runner::link_mount_ns_to_containers` exactly like its
/// children; dropping it here hid a single-process container running
/// `/tmp/evil`. "Attribution, not filter" (R31-07) applies to init too.
///
/// Parameterized on `proc_root` so the scanner is testable against a
/// tempdir; callers pass `/proc`.
pub fn scan_mount_namespace_anomalies_from(proc_root: &Path) -> Vec<MountNamespaceAnomaly> {
    let host_ns = match mnt_ns_inode(proc_root, 1) {
        Ok(ns) => ns,
        Err(e) => {
            coverage::record(format!(
                "mount namespace scan: {}/1/ns/mnt unreadable ({})",
                proc_root.display(),
                e.kind()
            ));
            return Vec::new();
        }
    };

    let mut pids: Vec<u32> = match fs::read_dir(proc_root) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .collect(),
        Err(e) => {
            coverage::record(format!(
                "mount namespace scan: {} unreadable ({e})",
                proc_root.display()
            ));
            return Vec::new();
        }
    };
    pids.sort_unstable();

    let total_pids = pids.len();
    let mut result = Vec::new();
    let mut denied = 0usize;

    for pid in pids.into_iter().take(MAX_PIDS) {
        let ns = match mnt_ns_inode(proc_root, pid) {
            Ok(ns) => ns,
            // R33-05: route every /proc/<pid> miss through the shared
            // classifier so the taxonomy lives in exactly one place
            // (safe_io::ProcMiss). Vanished = the pid exited between readdir
            // and readlink, a race, not a permission fact; Denied = the kernel
            // refused, a real coverage fact.
            Err(e) => match safe_io::proc_miss(&e) {
                safe_io::ProcMiss::Vanished => continue,
                _ => {
                    denied += 1;
                    continue;
                }
            },
        };
        if ns == host_ns {
            continue;
        }

        let comm_path = proc_root.join(format!("{pid}/comm"));
        let comm = safe_io::read_procfs_capped(&comm_path.to_string_lossy(), 4096)
            .ok()
            .map(|(c, _)| c.trim().to_string())
            .unwrap_or_else(|| "?".to_string());

        // Kernel worker threads have no user-space image: readlink on
        // /proc/<pid>/exe returns ENOENT. They cannot execute attacker code
        // and their mount namespace is inherited from the kernel at boot,
        // so they are noise in this list.
        let Some(exe_path) = fs::read_link(proc_root.join(format!("{pid}/exe")))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
        else {
            continue;
        };

        // R31-01: label system-managed prefixes and systemd units, never
        // drop them. `unshare -m` from a shell runs /usr/bin/bash under
        // session-N.scope — the case this scanner exists for. Consumers
        // filter by policy (ui.rs default; JSON always carries all).
        //
        // The predicate lives in utils.rs next to SYSTEM_BIN; the two answer
        // different questions and are deliberately not merged (see
        // is_system_managed_path docs).
        let sys_path = crate::utils::is_system_managed_path(&exe_path);

        result.push(MountNamespaceAnomaly {
            pid,
            comm,
            exe_path: Some(exe_path),
            mnt_ns: ns,
            container: None, // filled later by runner (R31-07)
            systemd_unit: systemd_unit(proc_root, pid),
            system_path: sys_path,
        });
    }

    result.sort_by_key(|a| a.pid);

    if denied > 0 {
        coverage::record(format!(
            "mount namespace scan: /proc/<pid>/ns/mnt unreadable for {denied} process(es)"
        ));
    }
    if total_pids > MAX_PIDS {
        // R31-02: pids are ascending, so take() drops the NEWEST processes —
        // exactly where a fresh `unshare` lands. Report the cap; the list
        // is a lower bound.
        coverage::record(format!(
            "mount namespace scan: {total_pids} processes, cap is {MAX_PIDS} — the \
             {} newest were NOT examined; this list is a LOWER BOUND",
            total_pids - MAX_PIDS
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fake_pid(root: &Path, pid: u32, mnt: &str, exe: &str, cgroup: &str) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(d.join("ns")).unwrap();
        symlink(mnt, d.join("ns/mnt")).unwrap();
        symlink(exe, d.join("exe")).unwrap();
        std::fs::write(d.join("comm"), "x\n").unwrap();
        std::fs::write(d.join("cgroup"), cgroup).unwrap();
    }

    #[test]
    fn a_container_init_in_a_foreign_namespace_is_reported() {
        // R33-02: init pid used to be dropped by the known-pid filter, so a
        // single-process container with an unpackaged entrypoint was invisible.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fake_pid(
            root,
            1,
            "mnt:[4026531840]",
            "/usr/lib/systemd/systemd",
            "0::/init.scope\n",
        );
        fake_pid(
            root,
            4242,
            "mnt:[4026532999]",
            "/tmp/evil",
            "0::/system.slice/docker-abc.scope\n",
        );
        fake_pid(
            root,
            4243,
            "mnt:[4026531840]",
            "/usr/bin/bash",
            "0::/user.slice/session-1.scope\n",
        );

        let out = scan_mount_namespace_anomalies_from(root);
        assert_eq!(out.len(), 1, "only the foreign-ns pid: {out:?}");
        assert_eq!(out[0].pid, 4242);
        assert_eq!(out[0].exe_path.as_deref(), Some("/tmp/evil"));
        assert_eq!(out[0].systemd_unit.as_deref(), Some("docker-abc.scope"));
        assert!(!out[0].system_path);
    }

    #[test]
    fn a_vanished_pid_is_not_counted_as_denied() {
        // R33-05: a dangling readdir entry (dir without ns/) must not produce
        // an "unreadable" coverage line. The behavioural guarantee is the
        // `continue` arm in the loop; we cannot assert on the coverage sink
        // from here without draining the global state.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fake_pid(root, 1, "mnt:[1]", "/sbin/init", "0::/init.scope\n");
        std::fs::create_dir_all(root.join("999")).unwrap(); // exited: no ns/mnt

        let out = scan_mount_namespace_anomalies_from(root);
        assert!(out.is_empty());
    }

    #[test]
    fn system_managed_paths_are_labelled_not_dropped() {
        // R31-01 invariant: a foreign-ns process running a system binary is
        // still emitted (system_path = true), because `unshare -m` from a
        // shell runs /usr/bin/bash and that is exactly the case we detect.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fake_pid(root, 1, "mnt:[1]", "/sbin/init", "0::/init.scope\n");
        fake_pid(
            root,
            777,
            "mnt:[2]",
            "/usr/bin/bash",
            "0::/user.slice/session-9.scope\n",
        );

        let out = scan_mount_namespace_anomalies_from(root);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 777);
        assert!(out[0].system_path);
    }

    #[test]
    fn cgroup_v1_prefers_the_systemd_hierarchy() {
        // R33-10: on a hybrid host the delegated `pids` controller can expose
        // a path with a `.scope` suffix that is not the unit that owns the
        // pid. Only the `name=systemd` hierarchy is authoritative; prefer it.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fake_pid(root, 1, "mnt:[1]", "/sbin/init", "0::/init.scope\n");
        fake_pid(
            root,
            777,
            "mnt:[2]",
            "/usr/bin/bash",
            "12:pids:/user.slice/session-1.scope\n\
             1:name=systemd:/system.slice/nginx.service\n",
        );

        let out = scan_mount_namespace_anomalies_from(root);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].systemd_unit.as_deref(),
            Some("nginx.service"),
            "must pick the systemd hierarchy, not the first line with a unit suffix"
        );
    }
}
