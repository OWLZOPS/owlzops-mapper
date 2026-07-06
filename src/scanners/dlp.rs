use crate::models::SecretLeak;
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

fn extract_process_name(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn scan_process_memory() -> Vec<SecretLeak> {
    let mut leaks = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return leaks;
    };

    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };

        let process_name = extract_process_name(pid);

        if process_name.is_empty() || process_name.starts_with("kworker") {
            continue;
        }

        // 1. Environment Variables
        if let Ok(env_data) = fs::read(format!("/proc/{}/environ", pid)) {
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
        if let Ok(cmd_data) = fs::read(format!("/proc/{}/cmdline", pid)) {
            for chunk in cmd_data.split(|&b| b == 0) {
                let Ok(arg) = std::str::from_utf8(chunk) else {
                    continue;
                };

                for &flag in SENSITIVE_FLAGS {
                    if arg.to_lowercase().starts_with(flag) {
                        leaks.push(SecretLeak {
                            pid,
                            process: process_name.clone(),
                            source: "cmdline".to_string(),
                            matched_key: flag.to_string(),
                        });
                    }
                }
            }
        }
    }

    leaks
}
