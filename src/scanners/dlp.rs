use crate::models::SecretLeak;
use crate::{coverage, safe_io};
use std::fmt::Write;
use std::fs;

const SENSITIVE_KEYS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "DO_PAT",
    "DATABASE_URL",
    "DB_PASSWORD",
    "MYSQL_PWD",
    "PGPASSWORD",
    "STRIPE_SECRET_KEY",
    "SLACK_BOT_TOKEN",
    "NPM_TOKEN",
];

const SENSITIVE_FLAGS: &[&str] = &["--password=", "-p=", "--token=", "--secret="];

fn starts_with_icase(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

pub fn scan_process_memory() -> Vec<SecretLeak> {
    let mut leaks = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return leaks;
    };

    // Reusable buffer for constructing /proc/<pid>/... paths
    let mut path_buf = String::with_capacity(64);

    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };

        // Process name
        path_buf.clear();
        let _ = write!(path_buf, "/proc/{}/comm", pid);
        let process_name = safe_io::read_file_capped(&path_buf, 4096)
            .map(|(s, truncated)| {
                if truncated {
                    coverage::record(format!("{} truncated", path_buf));
                }
                s.trim().to_string()
            })
            .unwrap_or_else(|_| "unknown".to_string());

        if process_name.is_empty() || process_name.starts_with("kworker") {
            continue;
        }

        // 1. Environment Variables
        path_buf.clear();
        let _ = write!(path_buf, "/proc/{}/environ", pid);
        if let Ok((env_data, truncated)) =
            safe_io::read_file_bytes_capped(&path_buf, safe_io::CAP_PROC_ENVIRON)
        {
            if truncated {
                coverage::record(format!("{} truncated", path_buf));
            }
            for chunk in env_data.split(|&b| b == 0) {
                let Ok(env_var) = std::str::from_utf8(chunk) else {
                    continue;
                };
                let Some((key, _value)) = env_var.split_once('=') else {
                    continue;
                };

                if SENSITIVE_KEYS
                    .iter()
                    .any(|&sk| key.eq_ignore_ascii_case(sk))
                {
                    leaks.push(SecretLeak {
                        pid,
                        process: process_name.clone(),
                        source: "environ".to_string(),
                        matched_key: key.to_string(),
                    });
                }
            }
        }

        // 2. Command Line Arguments
        path_buf.clear();
        let _ = write!(path_buf, "/proc/{}/cmdline", pid);
        if let Ok((cmd_data, truncated)) =
            safe_io::read_file_bytes_capped(&path_buf, safe_io::CAP_PROC_ENVIRON)
        {
            if truncated {
                coverage::record(format!("{} truncated", path_buf));
            }
            for chunk in cmd_data.split(|&b| b == 0) {
                let Ok(arg) = std::str::from_utf8(chunk) else {
                    continue;
                };

                for &flag in SENSITIVE_FLAGS {
                    if starts_with_icase(arg, flag) {
                        leaks.push(SecretLeak {
                            pid,
                            process: process_name.clone(),
                            source: "cmdline".to_string(),
                            matched_key: flag.to_string(),
                        });
                    }
                }

                // Cover `mysql -pSECRET` (without equals sign)
                if (process_name == "mysql" || process_name == "mysqldump")
                    && let Some(pwd) = arg.strip_prefix("-p")
                    && !pwd.is_empty()
                {
                    leaks.push(SecretLeak {
                        pid,
                        process: process_name.clone(),
                        source: "cmdline".to_string(),
                        matched_key: "mysql-password".to_string(),
                    });
                }
            }
        }
    }

    leaks
}
