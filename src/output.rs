use crate::cli::OutputFormat;
use crate::models::AgentReport;
use crate::ui;
use tracing::warn;

/// Output a single audit report in the requested format.
pub fn output_single(report: &AgentReport, format: &OutputFormat, output_file: Option<String>) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(report) {
            Ok(json) => println!("{json}"),
            Err(e) => warn!("error serializing Owlzops report: {e}"),
        },
        OutputFormat::Text => ui::render_dashboard(report),
        OutputFormat::Xlsx => {
            let filename = output_file.unwrap_or_else(|| {
                format!(
                    "owlzops-report-{}-{}.xlsx",
                    report.host.hostname,
                    chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
                )
            });
            match crate::exporters::xlsx::write_report(report, &filename) {
                Ok(_) => println!("✅ Excel report successfully generated: {filename}"),
                Err(e) => warn!("failed to generate Excel report: {e}"),
            }
        }
    }
}

/// Output a list of audit reports (multi‑host / fleet scan) in the requested format.
pub fn output_multi(reports: &[AgentReport], format: &OutputFormat, output_file: Option<String>) {
    match format {
        OutputFormat::Text => {
            if reports.len() == 1 {
                ui::render_dashboard(&reports[0]);
            } else {
                ui::render_multi_host_summary(reports);
            }
        }
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(reports) {
                println!("{json}");
            } else {
                warn!("error serializing multi‑host report");
            }
        }
        OutputFormat::Xlsx => {
            let filename = output_file.unwrap_or_else(|| {
                format!(
                    "owlzops-multi-{}.xlsx",
                    chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
                )
            });
            match crate::exporters::xlsx::write_multi_host_report(reports, &filename) {
                Ok(_) => println!("✅ Multi‑host Excel report: {filename}"),
                Err(e) => warn!("failed to generate Excel report: {e}"),
            }
        }
    }
}
