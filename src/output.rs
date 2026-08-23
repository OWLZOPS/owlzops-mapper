use crate::cli::OutputFormat;
use crate::models::AgentReport;
use crate::ui;
use std::path::Path;
use tracing::warn;

/// Convert a hostname into a safe filename component.
/// Allow-list approach mirrors validate_remote_path (R27-10): anything not
/// [A-Za-z0-9._-] is replaced with '_'; empty becomes "unknown".
/// Prevents path traversal via malicious remote hostname (R27-11).
#[cfg(feature = "local-scan")]
fn hostname_to_safe_filename(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "unknown".to_string()
    } else {
        cleaned
    }
}

#[cfg(feature = "local-scan")]
pub fn output_single(
    report: &AgentReport,
    format: &OutputFormat,
    output_file: Option<&Path>,
    verbose: bool,
) -> Result<(), String> {
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
            if let Some(path) = output_file {
                std::fs::write(path, &json).map_err(|e| format!("failed to write JSON: {e}"))?;
                println!("JSON report written to {}", path.display());
            } else {
                println!("{json}");
            }
            Ok(())
        }
        OutputFormat::Text => {
            ui::render_dashboard(report, verbose);
            Ok(())
        }
        OutputFormat::Xlsx => {
            let filename = output_file
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| {
                    format!(
                        "owlzops-report-{}-{}.xlsx",
                        hostname_to_safe_filename(&report.host.hostname),
                        chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
                    )
                });
            crate::exporters::xlsx::write_report(report, &filename).map_err(|e| {
                warn!("failed to generate Excel report: {e}");
                e.to_string()
            })?;
            println!("Excel report successfully generated: {filename}");
            Ok(())
        }
    }
}

pub fn output_multi(
    reports: &[AgentReport],
    format: &OutputFormat,
    output_file: Option<&Path>,
    verbose: bool,
) -> Result<(), String> {
    match format {
        OutputFormat::Text => {
            if reports.is_empty() {
                eprintln!("No reports to display.");
                return Ok(());
            }
            if reports.len() == 1 {
                ui::render_dashboard(&reports[0], verbose);
            } else {
                ui::render_multi_host_summary(reports);
                println!("\n--- Detail for first host ---\n");
                ui::render_dashboard(&reports[0], verbose);
            }
            Ok(())
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(reports).map_err(|e| e.to_string())?;
            if let Some(path) = output_file {
                std::fs::write(path, &json).map_err(|e| format!("failed to write JSON: {e}"))?;
                println!("JSON multi-report written to {}", path.display());
            } else {
                println!("{json}");
            }
            Ok(())
        }
        OutputFormat::Xlsx => {
            let filename = output_file
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| {
                    format!(
                        "owlzops-multi-{}.xlsx",
                        chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
                    )
                });
            crate::exporters::xlsx::write_multi_host_report(reports, &filename).map_err(|e| {
                warn!("failed to generate Excel report: {e}");
                e.to_string()
            })?;
            println!("Multi-host Excel report: {filename}");
            Ok(())
        }
    }
}
