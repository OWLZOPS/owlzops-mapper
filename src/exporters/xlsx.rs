use crate::models::{AgentReport, DiffReport, MultiHostDiff, PackageManager, Severity};
use rust_xlsxwriter::{Color, Format, FormatAlign, FormatBorder, Workbook, Worksheet, XlsxError};

// ---------------------------------------------------------------------------
// XLSX formula injection guard
// ---------------------------------------------------------------------------

/// Prefix a string with `'` if it starts with a character that might be
/// interpreted as a formula (`=`, `+`, `-`, `@`) by Excel / LibreOffice.
/// All attacker‑controlled strings written to a workbook MUST pass through
/// this function (see PIVOT-2 in threat model).
fn sanitize_xlsx(s: &str) -> String {
    match s.chars().next() {
        Some('=') | Some('+') | Some('-') | Some('@') => format!("'{}", s),
        _ => s.to_string(),
    }
}

// =====================================================================
// Pre-allocated formats (single allocation for the whole workbook)
// =====================================================================

pub struct Formats {
    header: Format,
    critical: Format,
    ok: Format,
    number: Format,
    even_row: Format,
    odd_row: Format,
    critical_even: Format,
    critical_odd: Format,
    warning_even: Format,
    warning_odd: Format,
    ok_even: Format,
    ok_odd: Format,
    #[allow(dead_code)]
    subtle: Format,
    #[allow(dead_code)]
    host_cell: Format,
}

impl Formats {
    fn new() -> Self {
        let even_bg = Color::RGB(0xF2F2F2);
        let white = Color::White;
        let critical_color = Color::RGB(0xC00000);
        let warning_color = Color::RGB(0xBF8F00);
        let ok_color = Color::RGB(0x375623);

        let header = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0x1F4E78))
            .set_font_color(Color::White)
            .set_align(FormatAlign::Left)
            .set_border(FormatBorder::Thin);

        let critical = Format::new()
            .set_font_color(critical_color)
            .set_bold()
            .set_border(FormatBorder::Thin);

        let ok = Format::new()
            .set_font_color(ok_color)
            .set_border(FormatBorder::Thin);

        let number = Format::new()
            .set_num_format("0.00")
            .set_border(FormatBorder::Thin);

        let even_row = Format::new()
            .set_background_color(even_bg)
            .set_border(FormatBorder::Thin);

        let odd_row = Format::new()
            .set_background_color(white)
            .set_border(FormatBorder::Thin);

        let critical_even = Format::new()
            .set_background_color(even_bg)
            .set_font_color(critical_color)
            .set_bold()
            .set_border(FormatBorder::Thin);

        let critical_odd = Format::new()
            .set_background_color(white)
            .set_font_color(critical_color)
            .set_bold()
            .set_border(FormatBorder::Thin);

        let warning_even = Format::new()
            .set_background_color(even_bg)
            .set_font_color(warning_color)
            .set_border(FormatBorder::Thin);

        let warning_odd = Format::new()
            .set_background_color(white)
            .set_font_color(warning_color)
            .set_border(FormatBorder::Thin);

        let ok_even = Format::new()
            .set_background_color(even_bg)
            .set_font_color(ok_color)
            .set_border(FormatBorder::Thin);

        let ok_odd = Format::new()
            .set_background_color(white)
            .set_font_color(ok_color)
            .set_border(FormatBorder::Thin);

        let subtle = Format::new()
            .set_font_size(10)
            .set_font_color(Color::RGB(0x808080))
            .set_italic();

        let host_cell = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0xE0E0E0))
            .set_border(FormatBorder::Thin);

        Self {
            header,
            critical,
            ok,
            number,
            even_row,
            odd_row,
            critical_even,
            critical_odd,
            warning_even,
            warning_odd,
            ok_even,
            ok_odd,
            subtle,
            host_cell,
        }
    }

    fn row_band(&self, row: u32) -> &Format {
        if row.is_multiple_of(2) {
            &self.even_row
        } else {
            &self.odd_row
        }
    }

    fn critical_band(&self, row: u32) -> &Format {
        if row.is_multiple_of(2) {
            &self.critical_even
        } else {
            &self.critical_odd
        }
    }

    #[allow(dead_code)]
    fn warning_band(&self, row: u32) -> &Format {
        if row.is_multiple_of(2) {
            &self.warning_even
        } else {
            &self.warning_odd
        }
    }

    fn ok_band(&self, row: u32) -> &Format {
        if row.is_multiple_of(2) {
            &self.ok_even
        } else {
            &self.ok_odd
        }
    }
}

// =====================================================================
// SheetWriter – a tiny builder that knows the current row and formats
// =====================================================================
struct SheetWriter<'a> {
    sheet: &'a mut Worksheet,
    row: u32,
    fmts: &'a Formats,
    col_widths: Vec<f64>,
}

impl<'a> SheetWriter<'a> {
    fn new(sheet: &'a mut Worksheet, fmts: &'a Formats) -> Self {
        Self {
            sheet,
            row: 0,
            fmts,
            col_widths: Vec::new(),
        }
    }

    fn next_row(&mut self) -> u32 {
        self.row += 1;
        self.row
    }

    fn observe_width(&mut self, col: usize, text: &str) {
        let len = text.len() as f64;
        if col >= self.col_widths.len() {
            self.col_widths.resize(col + 1, 0.0);
        }
        if len > self.col_widths[col] {
            self.col_widths[col] = len;
        }
    }

    fn write_header(&mut self, headers: &[&str]) -> Result<(), XlsxError> {
        for (col, h) in headers.iter().enumerate() {
            // Headers are static, no injection risk, but sanitize for consistency
            self.sheet.write_string_with_format(
                self.row,
                col as u16,
                sanitize_xlsx(h),
                &self.fmts.header,
            )?;
            self.observe_width(col, h);
        }
        self.next_row();
        Ok(())
    }

    fn write_kv_row(
        &mut self,
        key: &str,
        value: &str,
        value_fmt: Option<&Format>,
    ) -> Result<(), XlsxError> {
        let band = self.fmts.row_band(self.row);
        self.sheet
            .write_string_with_format(self.row, 0, sanitize_xlsx(key), band)?;
        let fmt = value_fmt.unwrap_or(band);
        self.sheet
            .write_string_with_format(self.row, 1, sanitize_xlsx(value), fmt)?;

        self.observe_width(0, key);
        self.observe_width(1, value);
        self.next_row();
        Ok(())
    }

    fn write_string(&mut self, col: usize, value: &str, fmt: &Format) -> Result<(), XlsxError> {
        self.sheet
            .write_string_with_format(self.row, col as u16, sanitize_xlsx(value), fmt)?;
        self.observe_width(col, value);
        Ok(())
    }

    fn write_number(&mut self, col: usize, value: f64, fmt: &Format) -> Result<(), XlsxError> {
        self.sheet
            .write_number_with_format(self.row, col as u16, value, fmt)?;
        let text = format!("{:.2}", value);
        self.observe_width(col, &text);
        Ok(())
    }

    #[allow(dead_code)]
    fn write_section_title(&mut self, title: &str) -> Result<(), XlsxError> {
        self.sheet.write_string_with_format(
            self.row,
            0,
            sanitize_xlsx(title),
            &self.fmts.header,
        )?;
        self.next_row();
        Ok(())
    }

    fn current_row(&self) -> u32 {
        self.row
    }

    fn apply_col_widths_with_min(&mut self, min_widths: &[f64]) -> Result<(), XlsxError> {
        for (col, &mw) in self.col_widths.iter().enumerate() {
            let min_w = min_widths.get(col).copied().unwrap_or(8.0);
            let w = (mw + 2.0).max(min_w);
            self.sheet.set_column_width(col as u16, w)?;
        }
        Ok(())
    }
}

// ---------- header helpers ----------

fn auto_fit_columns(
    sheet: &mut rust_xlsxwriter::Worksheet,
    data: &[Vec<String>],
    min_widths: &[f64],
) -> Result<(), XlsxError> {
    let col_count = data.iter().map(|row| row.len()).max().unwrap_or(0);
    let mut max_widths = vec![0.0f64; col_count];
    for row in data {
        for (col, cell) in row.iter().enumerate() {
            let len = cell.len() as f64;
            if len > max_widths[col] {
                max_widths[col] = len;
            }
        }
    }
    for (col, &mw) in max_widths.iter().enumerate() {
        let min_w = min_widths.get(col).copied().unwrap_or(8.0);
        sheet.set_column_width(col as u16, (mw + 2.0).max(min_w))?;
    }
    Ok(())
}

fn sanitize_sheet_name(
    name: &str,
    prefix: &str,
    used: &mut std::collections::HashSet<String>,
) -> String {
    const ILLEGAL: &[char] = &['\\', '/', '?', '*', '[', ']', ':'];
    let max_chars = 31usize.saturating_sub(prefix.len() + 1);
    let base: String = name
        .chars()
        .filter(|c| !ILLEGAL.contains(c))
        .take(max_chars)
        .collect();
    let mut candidate = format!("{}-{}", prefix, base);
    let mut n = 2u32;
    while used.contains(&candidate) {
        let suffix = format!("~{}", n);
        let trimmed_len = 31usize.saturating_sub(prefix.len() + 1 + suffix.len());
        let trimmed: String = base.chars().take(trimmed_len).collect();
        candidate = format!("{}-{}{}", prefix, trimmed, suffix);
        n += 1;
    }
    used.insert(candidate.clone());
    candidate
}

fn write_headers_at(
    sheet: &mut rust_xlsxwriter::Worksheet,
    row: u32,
    headers: &[&str],
    header_fmt: &Format,
) -> Result<(), XlsxError> {
    for (col, h) in headers.iter().enumerate() {
        sheet.write_string_with_format(row, col as u16, sanitize_xlsx(h), header_fmt)?;
    }
    Ok(())
}

// =====================================================================
// EXECUTIVE SUMMARY sheet
// =====================================================================
pub fn sheet_executive_summary(
    reports: &[AgentReport],
    multi_host: bool,
    fmts: &Formats,
) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name("Executive Summary")?;

    let title_fmt = Format::new()
        .set_bold()
        .set_font_size(20.0)
        .set_font_color(Color::RGB(0x1F4E78));
    let subtitle_fmt = Format::new()
        .set_font_size(12.0)
        .set_font_color(Color::RGB(0x808080));
    let large_score_fmt = Format::new()
        .set_bold()
        .set_font_size(40.0)
        .set_font_color(Color::RGB(0xC00000));
    let legend_fmt = Format::new()
        .set_font_size(9.0)
        .set_italic()
        .set_font_color(Color::RGB(0x808080));

    sheet.write_string_with_format(0, 0, "Owlzops Mapper", &title_fmt)?;
    sheet.write_string_with_format(1, 0, "Infrastructure Health Report", &subtitle_fmt)?;

    let mut current_row = 3u32;
    let mut data: Vec<Vec<String>> = Vec::new();

    if !multi_host && reports.len() == 1 {
        let report = &reports[0];

        sheet.write_string_with_format(current_row, 0, "Risk Score", &fmts.header)?;
        sheet.write_string_with_format(
            current_row,
            1,
            sanitize_xlsx(&format!("{}/100", report.risk_score)),
            &large_score_fmt,
        )?;
        data.push(vec![
            "Risk Score".to_string(),
            format!("{}/100", report.risk_score),
        ]);
        current_row += 2;

        let metrics: Vec<(&str, String, bool)> = vec![
            (
                "Firewall Active",
                report.network.firewall_active.to_string(),
                report.network.firewall_active,
            ),
            (
                "SSH Root Login",
                report.security.ssh_root_login_enabled.to_string(),
                !report.security.ssh_root_login_enabled,
            ),
            (
                "Security Updates Pending",
                report
                    .packages
                    .upgradable
                    .iter()
                    .any(|p| p.is_security)
                    .to_string(),
                !report.packages.upgradable.iter().any(|p| p.is_security),
            ),
            (
                "Backup Detected",
                (!report.host.backup_tools.is_empty()).to_string(),
                !report.host.backup_tools.is_empty(),
            ),
            (
                "NTP Synchronized",
                report.host.ntp_synchronized.to_string(),
                report.host.ntp_synchronized,
            ),
            (
                "Fail2Ban Active",
                report.security.fail2ban_active.to_string(),
                report.security.fail2ban_active,
            ),
            (
                "Sudo NOPASSWD Entries",
                report.security.sudo_nopasswd_entries.len().to_string(),
                report.security.sudo_nopasswd_entries.is_empty(),
            ),
        ];

        write_headers_at(&mut sheet, current_row, &["Check", "Status"], &fmts.header)?;
        data.push(vec!["Check".to_string(), "Status".to_string()]);
        current_row += 1;

        for (label, value, ok) in &metrics {
            let band = fmts.row_band(current_row);
            sheet.write_string_with_format(current_row, 0, sanitize_xlsx(label), band)?;
            let status_fmt = if *ok {
                fmts.ok_band(current_row)
            } else {
                fmts.critical_band(current_row)
            };
            sheet.write_string_with_format(current_row, 1, sanitize_xlsx(value), status_fmt)?;
            data.push(vec![label.to_string(), value.clone()]);
            current_row += 1;
        }

        current_row += 1;

        let mut criticals = Vec::new();
        if !report.network.firewall_active {
            criticals.push("Firewall is disabled");
        }
        if report.security.ssh_root_login_enabled {
            criticals.push("SSH root login is permitted");
        }
        if report.packages.upgradable.iter().any(|p| p.is_security) {
            criticals.push("Security updates are pending");
        }
        if report
            .network
            .ssl_certificates
            .iter()
            .any(|c| c.is_critical)
        {
            criticals.push("SSL certificate expiring within 7 days");
        }
        if report
            .host
            .failed_services
            .iter()
            .any(|s| s.contains(".service"))
        {
            criticals.push("Failed systemd services detected");
        }
        if report.host.backup_tools.is_empty() {
            criticals.push("No backup tools detected");
        }
        if !report.security.sudo_nopasswd_entries.is_empty() {
            criticals.push("Sudo NOPASSWD entries found");
        }
        if !report.host.ntp_synchronized {
            criticals.push("NTP is not synchronized");
        }

        if !criticals.is_empty() {
            sheet.write_string_with_format(current_row, 0, "Critical Findings", &fmts.header)?;
            data.push(vec!["Critical Findings".to_string(), String::new()]);
            current_row += 1;
            for c in &criticals {
                let band = fmts.row_band(current_row);
                sheet.write_string_with_format(current_row, 0, sanitize_xlsx(c), band)?;
                data.push(vec![c.to_string(), String::new()]);
                current_row += 1;
            }
        }
        if !report.scan_warnings.is_empty() {
            sheet.write_string_with_format(current_row, 0, "Data Quality", &fmts.header)?;
            sheet.write_string_with_format(
                current_row,
                1,
                "PARTIAL – scanners failed",
                fmts.critical_band(current_row),
            )?;
            data.push(vec![
                "Data Quality".to_string(),
                "PARTIAL – scanners failed".to_string(),
            ]);
            current_row += 1;
        }
    } else {
        write_headers_at(
            &mut sheet,
            current_row,
            &[
                "Host",
                "Risk",
                "Firewall",
                "SSH Root",
                "Security Updates",
                "Backup",
                "NTP",
                "Sudo NOPASSWD",
                "Sysctl Issues",
            ],
            &fmts.header,
        )?;
        data.push(vec![
            "Host".to_string(),
            "Risk".to_string(),
            "Firewall".to_string(),
            "SSH Root".to_string(),
            "Security Updates".to_string(),
            "Backup".to_string(),
            "NTP".to_string(),
            "Sudo NOPASSWD".to_string(),
            "Sysctl Issues".to_string(),
        ]);
        current_row += 1;

        let host_cell_fmt = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0xE0E0E0))
            .set_border(FormatBorder::Thin);

        for (idx, report) in reports.iter().enumerate() {
            if idx > 0 {
                let sep_fmt = Format::new().set_border(FormatBorder::Thin);
                sheet.write_string_with_format(current_row, 0, "", &sep_fmt)?;
                for col in 1..9 {
                    sheet.write_string_with_format(current_row, col, "", &sep_fmt)?;
                }
                data.push(vec![String::new(); 9]);
                current_row += 1;
            }

            let band = fmts.row_band(current_row);
            sheet.write_string_with_format(
                current_row,
                0,
                sanitize_xlsx(&report.host.hostname),
                &host_cell_fmt,
            )?;

            let score_fmt = if report.risk_score >= 70 {
                fmts.critical_band(current_row)
            } else if report.risk_score >= 40 {
                fmts.warning_band(current_row)
            } else {
                fmts.ok_band(current_row)
            };
            sheet.write_number_with_format(current_row, 1, report.risk_score as f64, score_fmt)?;

            sheet.write_string_with_format(
                current_row,
                2,
                if report.network.firewall_active {
                    "on"
                } else {
                    "OFF"
                },
                band,
            )?;
            sheet.write_string_with_format(
                current_row,
                3,
                if report.security.ssh_root_login_enabled {
                    "OPEN"
                } else {
                    "disabled"
                },
                band,
            )?;
            sheet.write_string_with_format(
                current_row,
                4,
                if report.packages.upgradable.iter().any(|p| p.is_security) {
                    "YES"
                } else {
                    "no"
                },
                band,
            )?;
            sheet.write_string_with_format(
                current_row,
                5,
                if report.host.backup_tools.is_empty() {
                    "MISSING"
                } else {
                    "found"
                },
                band,
            )?;
            sheet.write_string_with_format(
                current_row,
                6,
                if report.host.ntp_synchronized {
                    "synced"
                } else {
                    "NO"
                },
                band,
            )?;
            sheet.write_string_with_format(
                current_row,
                7,
                report.security.sudo_nopasswd_entries.len().to_string(),
                band,
            )?;
            sheet.write_string_with_format(
                current_row,
                8,
                report.security.sysctl_issues.len().to_string(),
                band,
            )?;

            data.push(vec![
                report.host.hostname.clone(),
                report.risk_score.to_string(),
                if report.network.firewall_active {
                    "on".into()
                } else {
                    "OFF".into()
                },
                if report.security.ssh_root_login_enabled {
                    "OPEN".into()
                } else {
                    "disabled".into()
                },
                if report.packages.upgradable.iter().any(|p| p.is_security) {
                    "YES".into()
                } else {
                    "no".into()
                },
                if report.host.backup_tools.is_empty() {
                    "MISSING".into()
                } else {
                    "found".into()
                },
                if report.host.ntp_synchronized {
                    "synced".into()
                } else {
                    "NO".into()
                },
                report.security.sudo_nopasswd_entries.len().to_string(),
                report.security.sysctl_issues.len().to_string(),
            ]);
            current_row += 1;
        }
    }

    current_row += 2;
    sheet.write_string_with_format(
        current_row,
        0,
        "Risk Score is calculated from firewall, SSH, updates, certificates, services, backups, NTP, sudo and sysctl checks. 0 = best, 100 = worst.",
        &legend_fmt,
    )?;

    let col_count = data.iter().map(|row| row.len()).max().unwrap_or(2);
    auto_fit_columns(&mut sheet, &data, &vec![12.0; col_count])?;

    sheet.set_print_fit_to_pages(1, 1);
    sheet.set_print_area(0, 0, current_row, col_count as u16 - 1)?;

    Ok(sheet)
}

// =====================================================================
// COMBINED HOST SHEET (all sections on one sheet)
// =====================================================================
fn sheet_host_combined(
    report: &AgentReport,
    sheet_name: &str,
    fmts: &Formats,
) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name(sheet_name)?;
    let mut w = SheetWriter::new(&mut sheet, fmts);

    let backup_str = if report.host.backup_tools.is_empty() {
        "None (CRITICAL)".to_string()
    } else {
        report.host.backup_tools.join(", ")
    };

    w.write_kv_row(
        "Risk Score",
        &format!("{}/100", report.risk_score),
        Some(if report.risk_score >= 70 {
            fmts.critical_band(w.current_row())
        } else if report.risk_score >= 40 {
            fmts.warning_band(w.current_row())
        } else {
            fmts.ok_band(w.current_row())
        }),
    )?;
    w.write_kv_row("Scan ID", &report.scan_id, None)?;
    w.write_kv_row("Timestamp", &report.timestamp, None)?;
    w.write_kv_row("Ran as root", &report.is_root_execution.to_string(), None)?;
    w.write_kv_row("Hostname", &report.host.hostname, None)?;
    w.write_kv_row("Provider", &report.host.hosting_provider, None)?;
    w.write_kv_row("External IP", &report.host.external_ipv4, None)?;
    w.write_kv_row("OS", &report.host.os_version, None)?;
    w.write_kv_row("Kernel", &report.host.kernel, None)?;
    w.write_kv_row(
        "Backup tools",
        &backup_str,
        Some(if report.host.backup_tools.is_empty() {
            fmts.critical_band(w.current_row())
        } else {
            fmts.ok_band(w.current_row())
        }),
    )?;
    w.write_kv_row("Uptime (days)", &report.host.uptime_days.to_string(), None)?;
    w.write_kv_row(
        "Reboot required",
        &report.host.reboot_required.to_string(),
        None,
    )?;
    w.write_kv_row("CPU cores", &report.host.cpu_cores.to_string(), None)?;
    w.write_kv_row(
        "RAM total (GB)",
        &format!("{:.2}", report.host.total_ram_mb as f64 / 1024.0),
        None,
    )?;
    w.write_kv_row(
        "Swap total (GB)",
        &format!("{:.2}", report.host.swap_total_mb as f64 / 1024.0),
        None,
    )?;
    w.write_kv_row(
        "Load average",
        &format!(
            "{:.2}, {:.2}, {:.2}",
            report.host.load_average.0, report.host.load_average.1, report.host.load_average.2
        ),
        None,
    )?;
    w.write_kv_row("OOM kills", &report.host.oom_kills.to_string(), None)?;
    w.write_kv_row(
        "Zombie processes",
        &report.host.zombie_processes.to_string(),
        None,
    )?;
    w.write_kv_row(
        "Security modules (LSM)",
        &report.host.security_modules.join(", "),
        None,
    )?;
    w.write_kv_row("Tech stack", &report.host.tech_stack.join(", "), None)?;

    w.next_row();
    w.write_header(&["Process", "PID", "RAM (MB)"])?;
    for p in &report.host.top_memory_processes {
        let band = fmts.row_band(w.current_row());
        w.write_string(0, &p.name, band)?;
        w.write_number(1, p.pid as f64, &fmts.number)?;
        w.write_number(2, p.memory_mb as f64, &fmts.number)?;
        w.next_row();
    }

    w.next_row();
    write_storage_section(&mut w, report, false)?;
    w.next_row();
    write_databases_section(&mut w, report, false)?;
    w.next_row();
    write_network_section(&mut w, report, false)?;
    w.next_row();
    write_security_section(&mut w, report, false)?;
    w.next_row();
    write_docker_section(&mut w, report, false)?;
    w.next_row();
    write_packages_section(&mut w, report, false)?;

    w.apply_col_widths_with_min(&[12.0, 12.0, 8.0, 12.0, 10.0, 10.0, 20.0, 12.0])?;
    Ok(sheet)
}

fn write_storage_section(
    w: &mut SheetWriter,
    report: &AgentReport,
    standalone: bool,
) -> Result<(), XlsxError> {
    if !standalone {
        w.write_section_title("Storage")?;
    }
    w.write_header(&[
        "Mount Point",
        "Total (GB)",
        "Used (GB)",
        "Usage %",
        "Inodes %",
    ])?;
    for disk in &report.storage.disks {
        if disk.total_gb == 0 {
            continue;
        }
        let usage_pct = (disk.used_gb as f64 / disk.total_gb as f64) * 100.0;
        let band = w.fmts.row_band(w.current_row());
        w.write_string(0, &disk.mount_point, band)?;
        w.write_number(1, disk.total_gb as f64, &w.fmts.number)?;
        w.write_number(2, disk.used_gb as f64, &w.fmts.number)?;
        let usage_fmt = if usage_pct > 90.0 {
            w.fmts.critical_band(w.current_row())
        } else if usage_pct > 75.0 {
            w.fmts.warning_band(w.current_row())
        } else {
            w.fmts.ok_band(w.current_row())
        };
        w.write_number(3, usage_pct, usage_fmt)?;
        let inode_str = disk
            .inode_usage_percent
            .clone()
            .unwrap_or_else(|| "-".to_string());
        w.write_string(4, &inode_str, band)?;
        w.next_row();
    }
    Ok(())
}

fn sheet_storage(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Storage")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);
    write_storage_section(&mut w, report, true)?;
    w.apply_col_widths_with_min(&[12.0, 10.0, 10.0, 10.0, 10.0])?;
    Ok(sheet)
}

fn write_security_section(
    w: &mut SheetWriter,
    report: &AgentReport,
    standalone: bool,
) -> Result<(), XlsxError> {
    if !standalone {
        w.write_section_title("Security")?;
    }

    let pa_fmt = if report.security.ssh_password_auth_enabled {
        Some(&w.fmts.critical)
    } else {
        Some(&w.fmts.ok)
    };
    w.write_kv_row(
        "SSH Password Auth Enabled",
        &report.security.ssh_password_auth_enabled.to_string(),
        pa_fmt,
    )?;

    let rl_fmt = if report.security.ssh_root_login_enabled {
        Some(&w.fmts.critical)
    } else {
        Some(&w.fmts.ok)
    };
    w.write_kv_row(
        "SSH Root Login Enabled",
        &report.security.ssh_root_login_enabled.to_string(),
        rl_fmt,
    )?;

    w.write_kv_row(
        "SSH Config Source",
        &report.security.ssh_config_source,
        None,
    )?;

    let f2b_fmt = if report.security.fail2ban_active {
        Some(&w.fmts.ok)
    } else {
        Some(&w.fmts.critical)
    };
    w.write_kv_row(
        "Fail2Ban Active",
        &report.security.fail2ban_active.to_string(),
        f2b_fmt,
    )?;

    let audit_fmt = if report.security.auditd_active {
        Some(&w.fmts.ok)
    } else {
        Some(&w.fmts.critical)
    };
    w.write_kv_row(
        "Auditd Active",
        &report.security.auditd_active.to_string(),
        audit_fmt,
    )?;

    if !report.host.failed_services.is_empty() {
        w.write_kv_row(
            "Failed Services",
            &report.host.failed_services.join(", "),
            Some(w.fmts.critical_band(w.current_row())),
        )?;
    }

    let ntp_value = match (report.host.ntp_synchronized, report.host.time_offset_ms) {
        (true, Some(ms)) => format!("yes ({:.1}ms offset)", ms),
        (true, None) => "yes".to_string(),
        (false, Some(ms)) => format!("no ({:.0}ms offset)", ms),
        (false, None) => "no".to_string(),
    };
    let ntp_fmt = if report.host.ntp_synchronized {
        Some(w.fmts.ok_band(w.current_row()))
    } else {
        Some(w.fmts.critical_band(w.current_row()))
    };
    w.write_kv_row("NTP Synchronized", &ntp_value, ntp_fmt)?;

    if !report.security.sudo_nopasswd_entries.is_empty() {
        w.write_kv_row(
            "Sudo NOPASSWD",
            &report.security.sudo_nopasswd_entries.join("; "),
            Some(w.fmts.critical_band(w.current_row())),
        )?;
    }
    if let Some(mode) = report.security.sudoers_mode {
        let (text, fmt) = if mode != 0o440 {
            (
                format!("{:o} (expected 0440)", mode),
                Some(w.fmts.critical_band(w.current_row())),
            )
        } else {
            (format!("{:o}", mode), Some(w.fmts.ok_band(w.current_row())))
        };
        w.write_kv_row("Sudoers Permissions", &text, fmt)?;
    }

    if !report.security.sysctl_issues.is_empty() {
        w.write_kv_row(
            "Sysctl Issues",
            &report.security.sysctl_issues.join("; "),
            Some(w.fmts.critical_band(w.current_row())),
        )?;
    }

    if !report.security.shell_users.is_empty() {
        w.next_row();
        w.write_header(&["User", "Last Login", "Last Remote SSH", "Authorized Keys"])?;
        for u in &report.security.shell_users {
            let band = w.fmts.row_band(w.current_row());
            w.write_string(0, &u.username, band)?;
            w.write_string(1, &u.last_login, band)?;
            w.write_string(2, &u.last_ssh_login, band)?;
            w.write_number(3, u.authorized_keys_count as f64, &w.fmts.number)?;
            w.next_row();
        }
    }
    Ok(())
}

fn sheet_security(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Security")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);
    write_security_section(&mut w, report, true)?;
    w.apply_col_widths_with_min(&[12.0, 12.0, 12.0, 10.0])?;
    Ok(sheet)
}

fn write_network_section(
    w: &mut SheetWriter,
    report: &AgentReport,
    standalone: bool,
) -> Result<(), XlsxError> {
    if !standalone {
        w.write_section_title("Network")?;
    }

    let fw_fmt = if report.network.firewall_active {
        Some(&w.fmts.ok)
    } else {
        Some(&w.fmts.critical)
    };
    w.write_kv_row(
        "Firewall Active",
        &report.network.firewall_active.to_string(),
        fw_fmt,
    )?;
    w.write_kv_row(
        "DNS Resolvers",
        &report.network.dns_resolvers.join(", "),
        None,
    )?;
    w.next_row();

    w.write_header(&["Protocol", "Port", "Process", "Bind Address"])?;
    for p in &report.network.listening_ports {
        let band = w.fmts.row_band(w.current_row());
        w.write_string(0, &p.protocol, band)?;
        w.write_string(1, &p.port, band)?;
        w.write_string(2, &p.process, band)?;
        let addr_fmt = if p.bind_address == "0.0.0.0" || p.bind_address == "::" {
            w.fmts.critical_band(w.current_row())
        } else {
            w.fmts.ok_band(w.current_row())
        };
        w.write_string(3, &p.bind_address, addr_fmt)?;
        w.next_row();
    }
    if !report.network.ssl_certificates.is_empty() {
        w.next_row();
        w.write_header(&["Domain", "Expires", "Days Left"])?;
        for cert in &report.network.ssl_certificates {
            let band = w.fmts.row_band(w.current_row());
            w.write_string(0, &cert.domain, band)?;
            w.write_string(1, &cert.expiry_date, band)?;
            if let Some(days) = cert.days_remaining {
                let days_fmt = if cert.is_critical {
                    w.fmts.critical_band(w.current_row())
                } else if cert.is_warning {
                    w.fmts.warning_band(w.current_row())
                } else {
                    w.fmts.ok_band(w.current_row())
                };
                w.write_number(2, days as f64, days_fmt)?;
            } else {
                w.write_string(2, "unknown", band)?;
            }
            w.next_row();
        }
    }

    if !report.network.custom_host_overrides.is_empty() {
        w.next_row();
        w.write_section_title("Custom /etc/hosts Overrides")?;
        for h in &report.network.custom_host_overrides {
            let band = w.fmts.row_band(w.current_row());
            w.write_string(0, h, band)?;
            w.next_row();
        }
    }
    Ok(())
}

fn sheet_network(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Network")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);
    write_network_section(&mut w, report, true)?;
    w.apply_col_widths_with_min(&[12.0, 12.0, 12.0, 12.0])?;
    Ok(sheet)
}

fn write_docker_section(
    w: &mut SheetWriter,
    report: &AgentReport,
    standalone: bool,
) -> Result<(), XlsxError> {
    if !report.topology.docker_active {
        return Ok(());
    }
    if !standalone {
        w.write_section_title("Docker")?;
    }
    w.write_kv_row(
        "Docker Active",
        &report.topology.docker_active.to_string(),
        None,
    )?;
    w.write_kv_row(
        "Total Images",
        &report.topology.images_count.to_string(),
        None,
    )?;

    let dangling_count = report.topology.dangling_images_count.to_string();
    let dangling_size = format!(
        "{:.2}",
        report.topology.total_dangling_size_mb as f64 / 1024.0
    );
    if report.topology.dangling_images_count > 0 {
        w.write_kv_row(
            "Dangling (Unused) Images",
            &dangling_count,
            Some(w.fmts.warning_band(w.current_row())),
        )?;
        w.write_kv_row(
            "Dangling Wasted Space (GB)",
            &dangling_size,
            Some(w.fmts.warning_band(w.current_row())),
        )?;
    } else {
        w.write_kv_row("Dangling (Unused) Images", &dangling_count, None)?;
        w.write_kv_row("Dangling Wasted Space (GB)", &dangling_size, None)?;
    }

    w.write_kv_row(
        "Dangling Volumes",
        &report.topology.dangling_volumes_count.to_string(),
        None,
    )?;

    if !report.topology.containers.is_empty() {
        w.next_row();
        w.write_header(&[
            "Name",
            "Image",
            "State",
            "Status",
            "Size (GB)",
            "Log Size (GB)",
            "Mounts",
            "Security Issues",
        ])?;
        for c in &report.topology.containers {
            let band = w.fmts.row_band(w.current_row());
            w.write_string(0, &c.name, band)?;
            w.write_string(1, &c.image, band)?;
            w.write_string(2, &c.state, band)?;
            w.write_string(3, &c.status, band)?;
            w.write_number(4, c.size_mb as f64 / 1024.0, &w.fmts.number)?;
            w.write_number(5, c.log_size_mb as f64 / 1024.0, &w.fmts.number)?;
            w.write_string(6, &c.mounts.join(" | "), band)?;
            let issues = c.security_issues();
            let issue_str = if issues.is_empty() {
                "-".to_string()
            } else {
                issues.join(", ")
            };
            if issue_str != "-" {
                w.write_string(7, &issue_str, w.fmts.critical_band(w.current_row()))?;
            } else {
                w.write_string(7, &issue_str, band)?;
            }
            w.next_row();
        }
    }
    Ok(())
}

fn sheet_docker(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Docker")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);
    write_docker_section(&mut w, report, true)?;
    w.apply_col_widths_with_min(&[12.0, 12.0, 8.0, 12.0, 10.0, 10.0, 20.0, 12.0])?;
    Ok(sheet)
}

fn write_packages_section(
    w: &mut SheetWriter,
    report: &AgentReport,
    standalone: bool,
) -> Result<(), XlsxError> {
    if !report.packages.manager.is_known() {
        return Ok(());
    }
    if !standalone {
        w.write_section_title("Packages")?;
    }
    let manager_str = match report.packages.manager {
        PackageManager::Apt => "apt (Debian/Ubuntu)",
        PackageManager::Dnf => "dnf (Fedora/RHEL)",
        PackageManager::Yum => "yum (RHEL/CentOS)",
        PackageManager::Pacman => "pacman (Arch)",
        PackageManager::Zypper => "zypper (openSUSE/SLES)",
        PackageManager::Unknown => "Unknown",
    };
    w.write_kv_row("Package Manager", manager_str, None)?;
    w.write_kv_row(
        "Installed Packages",
        &report.packages.installed_count.to_string(),
        None,
    )?;
    w.write_kv_row(
        "Cache Freshly Refreshed",
        &report.packages.cache_refreshed.to_string(),
        None,
    )?;

    if !report.packages.upgradable.is_empty() {
        w.next_row();
        w.write_header(&["Package", "Current", "Available", "Security"])?;
        let mut sorted: Vec<_> = report.packages.upgradable.iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.is_security));
        for p in &sorted {
            let band = w.fmts.row_band(w.current_row());
            w.write_string(0, &p.name, band)?;
            w.write_string(1, &p.current_version, band)?;
            w.write_string(2, &p.new_version, band)?;
            if p.is_security {
                w.write_string(3, "YES", w.fmts.critical_band(w.current_row()))?;
            } else {
                w.write_string(3, "-", band)?;
            }
            w.next_row();
        }
    }
    Ok(())
}

fn sheet_packages(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Packages")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);
    write_packages_section(&mut w, report, true)?;
    w.apply_col_widths_with_min(&[20.0, 20.0, 20.0, 10.0])?;
    Ok(sheet)
}

fn write_databases_section(
    w: &mut SheetWriter,
    report: &AgentReport,
    standalone: bool,
) -> Result<(), XlsxError> {
    if report.databases.is_empty() {
        return Ok(());
    }
    if !standalone {
        w.write_section_title("Databases")?;
    }
    w.write_header(&["Engine", "Version", "Data Directory", "Size (GB)"])?;
    for db in &report.databases {
        let band = w.fmts.row_band(w.current_row());
        w.write_string(0, &db.engine, band)?;
        w.write_string(1, &db.version, band)?;
        w.write_string(2, &db.data_dir, band)?;
        w.write_number(3, db.size_mb as f64 / 1024.0, &w.fmts.number)?;
        w.next_row();
    }
    Ok(())
}

fn sheet_databases(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Databases")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);
    write_databases_section(&mut w, report, true)?;
    w.apply_col_widths_with_min(&[12.0, 30.0, 20.0, 10.0])?;
    Ok(sheet)
}

// =====================================================================
// Wrappers for single‑host report (backward compatible)
// =====================================================================

fn sheet_overview(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Overview")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);

    let backup_str = if report.host.backup_tools.is_empty() {
        "None (CRITICAL)".to_string()
    } else {
        report.host.backup_tools.join(", ")
    };

    let rows: Vec<(&str, String, Option<&Format>)> = vec![
        ("Risk Score", format!("{}/100", report.risk_score), {
            if report.risk_score >= 70 {
                Some(fmts.critical_band(0))
            } else if report.risk_score >= 40 {
                Some(fmts.warning_band(0))
            } else {
                Some(fmts.ok_band(0))
            }
        }),
        ("Scan ID", report.scan_id.clone(), None),
        ("Timestamp", report.timestamp.clone(), None),
        ("Ran as root", report.is_root_execution.to_string(), None),
        ("Hostname", report.host.hostname.clone(), None),
        ("Provider", report.host.hosting_provider.clone(), None),
        ("External IP", report.host.external_ipv4.clone(), None),
        ("OS", report.host.os_version.clone(), None),
        ("Kernel", report.host.kernel.clone(), None),
        ("Backup tools", backup_str.clone(), {
            if report.host.backup_tools.is_empty() {
                Some(fmts.critical_band(w.current_row()))
            } else {
                Some(fmts.ok_band(w.current_row()))
            }
        }),
        ("Uptime (days)", report.host.uptime_days.to_string(), None),
        (
            "Reboot required",
            report.host.reboot_required.to_string(),
            None,
        ),
        ("CPU cores", report.host.cpu_cores.to_string(), None),
        (
            "RAM total (GB)",
            format!("{:.2}", report.host.total_ram_mb as f64 / 1024.0),
            None,
        ),
        (
            "Swap total (GB)",
            format!("{:.2}", report.host.swap_total_mb as f64 / 1024.0),
            None,
        ),
        (
            "Load average",
            format!(
                "{:.2}, {:.2}, {:.2}",
                report.host.load_average.0, report.host.load_average.1, report.host.load_average.2
            ),
            None,
        ),
        ("OOM kills", report.host.oom_kills.to_string(), None),
        (
            "Zombie processes",
            report.host.zombie_processes.to_string(),
            None,
        ),
        (
            "Security modules (LSM)",
            report.host.security_modules.join(", "),
            None,
        ),
        ("Tech stack", report.host.tech_stack.join(", "), None),
    ];

    for (key, value, value_fmt) in &rows {
        w.write_kv_row(key, value, *value_fmt)?;
    }

    if !report.coverage_warnings.is_empty() {
        w.write_section_title("Coverage Warnings")?;
        for cw in &report.coverage_warnings {
            let band = fmts.row_band(w.current_row());
            w.write_string(0, cw, band)?;
            w.next_row();
        }
    }

    w.next_row();

    let subtle = &fmts.subtle;
    w.sheet.write_formula_with_format(
        w.current_row(),
        0,
        r#"=HYPERLINK("https://owlzops.com", "Generated by Owlzops Mapper")"#,
        subtle,
    )?;
    w.next_row();
    w.sheet.write_formula_with_format(
        w.current_row(),
        0,
        r#"=HYPERLINK("mailto:hello@owlzops.com", "Need help with server audit or migration? Contact us: hello@owlzops.com")"#,
        subtle,
    )?;
    w.next_row();
    w.next_row();

    w.write_header(&["Process", "PID", "RAM (MB)"])?;
    for p in &report.host.top_memory_processes {
        let band = fmts.row_band(w.current_row());
        w.write_string(0, &p.name, band)?;
        w.write_number(1, p.pid as f64, &fmts.number)?;
        w.write_number(2, p.memory_mb as f64, &fmts.number)?;
        w.next_row();
    }

    w.apply_col_widths_with_min(&[20.0, 15.0, 15.0])?;
    Ok(sheet)
}

// =====================================================================
// WRITE REPORT (single host)
// =====================================================================
pub fn write_report(report: &AgentReport, path: &str) -> Result<(), XlsxError> {
    let fmts = Formats::new();
    let mut workbook = Workbook::new();

    workbook.push_worksheet(sheet_executive_summary(
        std::slice::from_ref(report),
        false,
        &fmts,
    )?);
    workbook.push_worksheet(sheet_overview(report, &fmts)?);
    workbook.push_worksheet(sheet_storage(report, &fmts)?);
    workbook.push_worksheet(sheet_databases(report, &fmts)?);
    workbook.push_worksheet(sheet_network(report, &fmts)?);
    workbook.push_worksheet(sheet_security(report, &fmts)?);
    workbook.push_worksheet(sheet_docker(report, &fmts)?);
    workbook.push_worksheet(sheet_packages(report, &fmts)?);

    workbook.save(path)?;
    Ok(())
}

// =====================================================================
// WRITE MULTI-HOST REPORT
// =====================================================================
pub fn write_multi_host_report(reports: &[AgentReport], path: &str) -> Result<(), XlsxError> {
    let fmts = Formats::new();
    let mut workbook = Workbook::new();

    workbook.push_worksheet(sheet_executive_summary(reports, true, &fmts)?);

    let mut used_names = std::collections::HashSet::new();
    for report in reports {
        let name = sanitize_sheet_name(&report.host.hostname, "Overview", &mut used_names);
        workbook.push_worksheet(sheet_host_combined(report, &name, &fmts)?);
    }

    workbook.save(path)?;
    Ok(())
}

// =====================================================================
// DIFF sheets
// =====================================================================

pub fn write_diff_sheet(
    report: &DiffReport,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut workbook = Workbook::new();
    let sheet = workbook.add_worksheet().set_name("Changes")?;

    let header_fmt = Format::new().set_bold().set_background_color(Color::Gray);

    sheet.write_with_format(0, 0, "Field", &header_fmt)?;
    sheet.write_with_format(0, 1, "Before", &header_fmt)?;
    sheet.write_with_format(0, 2, "After", &header_fmt)?;
    sheet.write_with_format(0, 3, "Severity", &header_fmt)?;

    let green = Format::new().set_font_color(Color::Green);
    let red = Format::new().set_font_color(Color::Red);
    let yellow = Format::new().set_font_color(Color::RGB(0xCCAA00));

    for (i, change) in report.changes.iter().enumerate() {
        let row = (i + 1) as u32;
        sheet.write(row, 0, sanitize_xlsx(&change.field))?;
        sheet.write(
            row,
            1,
            sanitize_xlsx(change.before.as_deref().unwrap_or("-")),
        )?;
        sheet.write(
            row,
            2,
            sanitize_xlsx(change.after.as_deref().unwrap_or("-")),
        )?;

        let (sev_text, fmt) = match change.severity {
            Severity::Improved => ("Improved", &green),
            Severity::Degraded => ("Degraded", &red),
            Severity::Changed => ("Changed", &yellow),
        };
        sheet.write_with_format(row, 3, sev_text, fmt)?;
    }

    // Set column widths for readability
    sheet.set_column_width(0, 44)?; // Field
    sheet.set_column_width(1, 30)?; // Before
    sheet.set_column_width(2, 30)?; // After
    sheet.set_column_width(3, 12)?; // Severity

    workbook.save(file_path)?;
    Ok(())
}

pub fn write_multi_diff_xlsx(
    diffs: &[MultiHostDiff],
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut workbook = Workbook::new();
    let sheet = workbook.add_worksheet().set_name("Multi-Host Changes")?;

    let header_fmt = Format::new().set_bold().set_background_color(Color::Gray);
    sheet.write_with_format(0, 0, "Host", &header_fmt)?;
    sheet.write_with_format(0, 1, "Field", &header_fmt)?;
    sheet.write_with_format(0, 2, "Before", &header_fmt)?;
    sheet.write_with_format(0, 3, "After", &header_fmt)?;
    sheet.write_with_format(0, 4, "Severity", &header_fmt)?;

    let green = Format::new().set_font_color(Color::Green);
    let red = Format::new().set_font_color(Color::Red);
    let yellow = Format::new().set_font_color(Color::RGB(0xCCAA00));

    let mut row = 1u32;
    for mh in diffs {
        for change in &mh.diff.changes {
            sheet.write(row, 0, sanitize_xlsx(&mh.hostname))?;
            sheet.write(row, 1, sanitize_xlsx(&change.field))?;
            sheet.write(
                row,
                2,
                sanitize_xlsx(change.before.as_deref().unwrap_or("-")),
            )?;
            sheet.write(
                row,
                3,
                sanitize_xlsx(change.after.as_deref().unwrap_or("-")),
            )?;
            let (sev_text, fmt) = match change.severity {
                Severity::Improved => ("Improved", &green),
                Severity::Degraded => ("Degraded", &red),
                Severity::Changed => ("Changed", &yellow),
            };
            sheet.write_with_format(row, 4, sev_text, fmt)?;
            row += 1;
        }
    }

    // Set column widths for multi-host diff
    sheet.set_column_width(0, 30)?; // Host
    sheet.set_column_width(1, 44)?; // Field
    sheet.set_column_width(2, 30)?; // Before
    sheet.set_column_width(3, 30)?; // After
    sheet.set_column_width(4, 12)?; // Severity

    workbook.save(file_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    fn minimal_report() -> AgentReport {
        AgentReport {
            scan_id: "test".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            version: "0.4.3".into(),
            duration_secs: 1.0,
            risk_score: 10,
            is_root_execution: true,
            scan_warnings: Vec::new(),
            coverage_warnings: Vec::new(),
            scoring_version: 1,
            host: HostInfo {
                hostname: "testhost".into(),
                backup_tools: vec!["restic".into()],
                ntp_synchronized: true,
                ..Default::default()
            },
            databases: vec![],
            network: NetworkInfo {
                firewall_active: true,
                ..Default::default()
            },
            storage: StorageInfo::default(),
            topology: TopologyInfo::default(),
            security: SecurityInfo {
                ssh_root_login_enabled: false,
                ssh_password_auth_enabled: false,
                fail2ban_active: true,
                auditd_active: true,
                ..Default::default()
            },
            packages: PackagesInfo {
                installed_count: 100,
                ..Default::default()
            },
        }
    }

    #[test]
    fn write_report_creates_nonempty_file() {
        let tmp = std::env::temp_dir().join(format!("owlzops-test-{}.xlsx", uuid::Uuid::new_v4()));
        let report = minimal_report();
        let result = write_report(&report, &tmp.to_string_lossy());
        assert!(result.is_ok());
        assert!(tmp.exists());
        let metadata = std::fs::metadata(&tmp).unwrap();
        assert!(metadata.len() > 0);
        let _ = std::fs::remove_file(&tmp);
    }
}
