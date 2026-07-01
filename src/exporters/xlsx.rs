use crate::models::{AgentReport, DiffReport, MultiHostDiff, PackageManager, Severity};
use rust_xlsxwriter::{Color, Format, FormatAlign, FormatBorder, Workbook, Worksheet, XlsxError};
// =====================================================================
// Pre-allocated formats (single allocation for the whole workbook)
// =====================================================================

struct Formats {
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
            self.sheet
                .write_string_with_format(self.row, col as u16, *h, &self.fmts.header)?;
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
            .write_string_with_format(self.row, 0, key, band)?;
        let fmt = value_fmt.unwrap_or(band);
        self.sheet
            .write_string_with_format(self.row, 1, value, fmt)?;

        self.observe_width(0, key);
        self.observe_width(1, value);
        self.next_row();
        Ok(())
    }

    // Write a string to a specific column with an explicit format
    fn write_string(&mut self, col: usize, value: &str, fmt: &Format) -> Result<(), XlsxError> {
        self.sheet
            .write_string_with_format(self.row, col as u16, value, fmt)?;
        self.observe_width(col, value);
        Ok(())
    }

    // Write a number to a specific column with an explicit format
    fn write_number(&mut self, col: usize, value: f64, fmt: &Format) -> Result<(), XlsxError> {
        self.sheet
            .write_number_with_format(self.row, col as u16, value, fmt)?;
        // Width observation for numbers: just use a reasonable estimate
        let text = format!("{:.2}", value);
        self.observe_width(col, &text);
        Ok(())
    }

    #[allow(dead_code)]
    fn write_section_title(&mut self, title: &str) -> Result<(), XlsxError> {
        self.sheet
            .write_string_with_format(self.row, 0, title, &self.fmts.header)?;
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

// ---------- basic formats (thin borders) ----------
fn header_format() -> Format {
    Format::new()
        .set_bold()
        .set_background_color(Color::RGB(0x1F4E78))
        .set_font_color(Color::White)
        .set_align(FormatAlign::Left)
        .set_border(FormatBorder::Thin)
}

fn critical_format() -> Format {
    Format::new()
        .set_font_color(Color::RGB(0xC00000))
        .set_bold()
        .set_border(FormatBorder::Thin)
}

fn ok_format() -> Format {
    Format::new()
        .set_font_color(Color::RGB(0x375623))
        .set_border(FormatBorder::Thin)
}

fn number_format() -> Format {
    Format::new()
        .set_num_format("0.00")
        .set_border(FormatBorder::Thin)
}

// ---------- row banding (background + borders) ----------
fn even_row_fmt() -> Format {
    Format::new()
        .set_background_color(Color::RGB(0xF2F2F2))
        .set_border(FormatBorder::Thin)
}

fn odd_row_fmt() -> Format {
    Format::new()
        .set_background_color(Color::White)
        .set_border(FormatBorder::Thin)
}

fn row_band(row: u32) -> Format {
    if row.is_multiple_of(2) {
        even_row_fmt()
    } else {
        odd_row_fmt()
    }
}

fn critical_band(row: u32) -> Format {
    let bg = if row.is_multiple_of(2) {
        Color::RGB(0xF2F2F2)
    } else {
        Color::White
    };
    Format::new()
        .set_background_color(bg)
        .set_font_color(Color::RGB(0xC00000))
        .set_bold()
        .set_border(FormatBorder::Thin)
}
#[allow(dead_code)]
fn warning_band(row: u32) -> Format {
    let bg = if row.is_multiple_of(2) {
        Color::RGB(0xF2F2F2)
    } else {
        Color::White
    };
    Format::new()
        .set_background_color(bg)
        .set_font_color(Color::RGB(0xBF8F00))
        .set_border(FormatBorder::Thin)
}

fn ok_band(row: u32) -> Format {
    let bg = if row.is_multiple_of(2) {
        Color::RGB(0xF2F2F2)
    } else {
        Color::White
    };
    Format::new()
        .set_background_color(bg)
        .set_font_color(Color::RGB(0x375623))
        .set_border(FormatBorder::Thin)
}

// ---------- header helpers ----------
fn write_headers(
    sheet: &mut rust_xlsxwriter::Worksheet,
    headers: &[&str],
) -> Result<(), XlsxError> {
    let fmt = header_format();
    for (col, h) in headers.iter().enumerate() {
        sheet.write_string_with_format(0, col as u16, *h, &fmt)?;
        sheet.set_column_width(col as u16, (h.len() as f64 + 4.0).max(12.0))?;
    }
    Ok(())
}

fn write_headers_at(
    sheet: &mut rust_xlsxwriter::Worksheet,
    row: u32,
    headers: &[&str],
) -> Result<(), XlsxError> {
    let fmt = header_format();
    for (col, h) in headers.iter().enumerate() {
        sheet.write_string_with_format(row, col as u16, *h, &fmt)?;
    }
    Ok(())
}

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

/// Sanitize a hostname for use as an Excel sheet name.
/// Sheet names must be ≤ 31 chars and must not contain: \ / ? * [ ] :
fn sanitize_sheet_name(name: &str, prefix: &str) -> String {
    const ILLEGAL: &[char] = &['\\', '/', '?', '*', '[', ']', ':'];
    let max_chars = 31usize.saturating_sub(prefix.len() + 1); // +1 for '-'
    let sanitized: String = name
        .chars()
        .filter(|c| !ILLEGAL.contains(c))
        .take(max_chars)
        .collect();
    format!("{}-{}", prefix, sanitized)
}

// =====================================================================
// EXECUTIVE SUMMARY sheet
// =====================================================================
pub fn sheet_executive_summary(
    reports: &[AgentReport],
    multi_host: bool,
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

        sheet.write_string_with_format(current_row, 0, "Risk Score", &header_format())?;
        sheet.write_string_with_format(
            current_row,
            1,
            format!("{}/100", report.risk_score),
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

        write_headers_at(&mut sheet, current_row, &["Check", "Status"])?;
        data.push(vec!["Check".to_string(), "Status".to_string()]);
        current_row += 1;

        for (label, value, ok) in &metrics {
            let band = row_band(current_row);
            sheet.write_string_with_format(current_row, 0, *label, &band)?;
            let status_fmt = if *ok {
                ok_band(current_row)
            } else {
                critical_band(current_row)
            };
            sheet.write_string_with_format(current_row, 1, value, &status_fmt)?;
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
            sheet.write_string_with_format(
                current_row,
                0,
                "Critical Findings",
                &header_format(),
            )?;
            data.push(vec!["Critical Findings".to_string(), String::new()]);
            current_row += 1;
            for c in &criticals {
                let band = row_band(current_row);
                sheet.write_string_with_format(current_row, 0, *c, &band)?;
                data.push(vec![c.to_string(), String::new()]);
                current_row += 1;
            }
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

            let band = row_band(current_row);
            sheet.write_string_with_format(
                current_row,
                0,
                &report.host.hostname,
                &host_cell_fmt,
            )?;

            let score_fmt = if report.risk_score >= 70 {
                critical_band(current_row)
            } else if report.risk_score >= 40 {
                warning_band(current_row)
            } else {
                ok_band(current_row)
            };
            sheet.write_number_with_format(current_row, 1, report.risk_score as f64, &score_fmt)?;

            sheet.write_string_with_format(
                current_row,
                2,
                if report.network.firewall_active {
                    "on"
                } else {
                    "OFF"
                },
                &band,
            )?;
            sheet.write_string_with_format(
                current_row,
                3,
                if report.security.ssh_root_login_enabled {
                    "OPEN"
                } else {
                    "disabled"
                },
                &band,
            )?;
            sheet.write_string_with_format(
                current_row,
                4,
                if report.packages.upgradable.iter().any(|p| p.is_security) {
                    "YES"
                } else {
                    "no"
                },
                &band,
            )?;
            sheet.write_string_with_format(
                current_row,
                5,
                if report.host.backup_tools.is_empty() {
                    "MISSING"
                } else {
                    "found"
                },
                &band,
            )?;
            sheet.write_string_with_format(
                current_row,
                6,
                if report.host.ntp_synchronized {
                    "synced"
                } else {
                    "NO"
                },
                &band,
            )?;
            sheet.write_string_with_format(
                current_row,
                7,
                report.security.sudo_nopasswd_entries.len().to_string(),
                &band,
            )?;
            sheet.write_string_with_format(
                current_row,
                8,
                report.security.sysctl_issues.len().to_string(),
                &band,
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
pub fn sheet_host_combined(
    report: &AgentReport,
    sheet_name: &str,
) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name(sheet_name)?;

    let mut current_row = 0u32;

    // ---------- Overview section ----------
    write_headers_at(&mut sheet, current_row, &["Field", "Value"])?;
    current_row += 1;

    let backup_str = if report.host.backup_tools.is_empty() {
        "None (CRITICAL)".to_string()
    } else {
        report.host.backup_tools.join(", ")
    };

    let rows: Vec<(&str, String)> = vec![
        ("Risk Score", format!("{}/100", report.risk_score)),
        ("Scan ID", report.scan_id.clone()),
        ("Timestamp", report.timestamp.clone()),
        ("Ran as root", report.is_root_execution.to_string()),
        ("Hostname", report.host.hostname.clone()),
        ("Provider", report.host.hosting_provider.clone()),
        ("External IP", report.host.external_ipv4.clone()),
        ("OS", report.host.os_version.clone()),
        ("Kernel", report.host.kernel.clone()),
        ("Backup tools", backup_str),
        ("Uptime (days)", report.host.uptime_days.to_string()),
        ("Reboot required", report.host.reboot_required.to_string()),
        ("CPU cores", report.host.cpu_cores.to_string()),
        (
            "RAM total (GB)",
            format!("{:.2}", report.host.total_ram_mb as f64 / 1024.0),
        ),
        (
            "Swap total (GB)",
            format!("{:.2}", report.host.swap_total_mb as f64 / 1024.0),
        ),
        (
            "Load average",
            format!(
                "{:.2}, {:.2}, {:.2}",
                report.host.load_average.0, report.host.load_average.1, report.host.load_average.2
            ),
        ),
        ("OOM kills", report.host.oom_kills.to_string()),
        ("Zombie processes", report.host.zombie_processes.to_string()),
        (
            "Security modules (LSM)",
            report.host.security_modules.join(", "),
        ),
        ("Tech stack", report.host.tech_stack.join(", ")),
    ];

    for (label, value) in &rows {
        let band = row_band(current_row);
        sheet.write_string_with_format(current_row, 0, *label, &band)?;
        if *label == "Risk Score" {
            let score_fmt = if report.risk_score >= 70 {
                critical_band(current_row)
            } else if report.risk_score >= 40 {
                warning_band(current_row)
            } else {
                ok_band(current_row)
            };
            sheet.write_string_with_format(current_row, 1, value, &score_fmt)?;
        } else if *label == "Backup tools" {
            let bk_fmt = if report.host.backup_tools.is_empty() {
                critical_band(current_row)
            } else {
                ok_band(current_row)
            };
            sheet.write_string_with_format(current_row, 1, value, &bk_fmt)?;
        } else {
            sheet.write_string_with_format(current_row, 1, value, &band)?;
        }
        current_row += 1;
    }

    current_row += 1;
    let subtle = Format::new()
        .set_font_size(10)
        .set_font_color(Color::RGB(0x808080))
        .set_italic();
    sheet.write_formula_with_format(
        current_row,
        0,
        r#"=HYPERLINK("https://owlzops.com", "Generated by Owlzops Mapper")"#,
        &subtle,
    )?;
    current_row += 1;
    sheet.write_formula_with_format(
        current_row,
        0,
        r#"=HYPERLINK("mailto:hello@owlzops.com", "Need help with server audit or migration? Contact us: hello@owlzops.com")"#,
        &subtle,
    )?;
    current_row += 2;

    sheet.write_string_with_format(current_row, 0, "Top Memory Processes", &header_format())?;
    sheet.write_string_with_format(current_row, 1, "PID", &header_format())?;
    sheet.write_string_with_format(current_row, 2, "RAM (MB)", &header_format())?;
    current_row += 1;
    for p in &report.host.top_memory_processes {
        let band = row_band(current_row);
        sheet.write_string_with_format(current_row, 0, &p.name, &band)?;
        sheet.write_number_with_format(current_row, 1, p.pid as f64, &number_format())?;
        sheet.write_number_with_format(current_row, 2, p.memory_mb as f64, &number_format())?;
        current_row += 1;
    }

    current_row += 2;

    // ---------- Storage section ----------
    sheet.write_string_with_format(current_row, 0, "Storage", &header_format())?;
    current_row += 1;
    write_headers_at(
        &mut sheet,
        current_row,
        &[
            "Mount Point",
            "Total (GB)",
            "Used (GB)",
            "Usage %",
            "Inodes %",
        ],
    )?;
    current_row += 1;

    let num_fmt = number_format();
    for disk in &report.storage.disks {
        if disk.total_gb == 0 {
            continue;
        }
        let usage_pct = (disk.used_gb as f64 / disk.total_gb as f64) * 100.0;
        let band = row_band(current_row);
        sheet.write_string_with_format(current_row, 0, &disk.mount_point, &band)?;
        sheet.write_number_with_format(current_row, 1, disk.total_gb as f64, &num_fmt)?;
        sheet.write_number_with_format(current_row, 2, disk.used_gb as f64, &num_fmt)?;
        let usage_fmt = if usage_pct > 90.0 {
            critical_band(current_row)
        } else if usage_pct > 75.0 {
            warning_band(current_row)
        } else {
            ok_band(current_row)
        };
        sheet.write_number_with_format(current_row, 3, usage_pct, &usage_fmt)?;
        let inode_str = disk
            .inode_usage_percent
            .clone()
            .unwrap_or_else(|| "-".to_string());
        sheet.write_string_with_format(current_row, 4, &inode_str, &band)?;
        current_row += 1;
    }
    current_row += 2;

    // ---------- Databases section ----------
    if !report.databases.is_empty() {
        sheet.write_string_with_format(current_row, 0, "Databases", &header_format())?;
        current_row += 1;
        write_headers_at(
            &mut sheet,
            current_row,
            &["Engine", "Version", "Data Directory", "Size (GB)"],
        )?;
        current_row += 1;
        for db in &report.databases {
            let band = row_band(current_row);
            sheet.write_string_with_format(current_row, 0, &db.engine, &band)?;
            sheet.write_string_with_format(current_row, 1, &db.version, &band)?;
            sheet.write_string_with_format(current_row, 2, &db.data_dir, &band)?;
            sheet.write_number_with_format(current_row, 3, db.size_mb as f64 / 1024.0, &num_fmt)?;
            current_row += 1;
        }
        current_row += 2;
    }

    // ---------- Network section ----------
    sheet.write_string_with_format(current_row, 0, "Network", &header_format())?;
    current_row += 1;

    sheet.write_string_with_format(current_row, 0, "Firewall Active", &header_format())?;
    sheet.write_string_with_format(
        current_row,
        1,
        report.network.firewall_active.to_string(),
        &row_band(current_row),
    )?;
    current_row += 1;
    sheet.write_string_with_format(current_row, 0, "DNS Resolvers", &header_format())?;
    sheet.write_string_with_format(
        current_row,
        1,
        report.network.dns_resolvers.join(", "),
        &row_band(current_row),
    )?;
    current_row += 2;

    write_headers_at(
        &mut sheet,
        current_row,
        &["Protocol", "Port", "Process", "Bind Address"],
    )?;
    current_row += 1;
    for p in &report.network.listening_ports {
        let band = row_band(current_row);
        sheet.write_string_with_format(current_row, 0, &p.protocol, &band)?;
        sheet.write_string_with_format(current_row, 1, &p.port, &band)?;
        sheet.write_string_with_format(current_row, 2, &p.process, &band)?;
        let addr_fmt = if p.bind_address == "0.0.0.0" || p.bind_address == "::" {
            critical_band(current_row)
        } else {
            ok_band(current_row)
        };
        sheet.write_string_with_format(current_row, 3, &p.bind_address, &addr_fmt)?;
        current_row += 1;
    }
    current_row += 1;

    if !report.network.ssl_certificates.is_empty() {
        write_headers_at(&mut sheet, current_row, &["Domain", "Expires", "Days Left"])?;
        current_row += 1;
        for cert in &report.network.ssl_certificates {
            let band = row_band(current_row);
            sheet.write_string_with_format(current_row, 0, &cert.domain, &band)?;
            sheet.write_string_with_format(current_row, 1, &cert.expiry_date, &band)?;
            match cert.days_remaining {
                Some(d) if cert.is_critical => sheet.write_number_with_format(
                    current_row,
                    2,
                    d as f64,
                    &critical_band(current_row),
                )?,
                Some(d) if cert.is_warning => sheet.write_number_with_format(
                    current_row,
                    2,
                    d as f64,
                    &warning_band(current_row),
                )?,
                Some(d) => sheet.write_number_with_format(
                    current_row,
                    2,
                    d as f64,
                    &ok_band(current_row),
                )?,
                None => sheet.write_string_with_format(current_row, 2, "unknown", &band)?,
            };
            current_row += 1;
        }
        current_row += 1;
    }

    // ---------- Security section ----------
    sheet.write_string_with_format(current_row, 0, "Security", &header_format())?;
    current_row += 1;

    let risky = critical_format();
    let safe = ok_format();

    sheet.write_string_with_format(
        current_row,
        0,
        "SSH Password Auth Enabled",
        &header_format(),
    )?;
    let pa_fmt = if report.security.ssh_password_auth_enabled {
        &risky
    } else {
        &safe
    };
    sheet.write_string_with_format(
        current_row,
        1,
        report.security.ssh_password_auth_enabled.to_string(),
        pa_fmt,
    )?;
    current_row += 1;

    sheet.write_string_with_format(current_row, 0, "SSH Root Login Enabled", &header_format())?;
    let rl_fmt = if report.security.ssh_root_login_enabled {
        &risky
    } else {
        &safe
    };
    sheet.write_string_with_format(
        current_row,
        1,
        report.security.ssh_root_login_enabled.to_string(),
        rl_fmt,
    )?;
    current_row += 1;

    sheet.write_string_with_format(current_row, 0, "SSH Config Source", &header_format())?;
    sheet.write_string_with_format(
        current_row,
        1,
        &report.security.ssh_config_source,
        &row_band(current_row),
    )?;
    current_row += 1;

    sheet.write_string_with_format(current_row, 0, "Fail2Ban Active", &header_format())?;
    let f2b_fmt = if report.security.fail2ban_active {
        &safe
    } else {
        &risky
    };
    sheet.write_string_with_format(
        current_row,
        1,
        report.security.fail2ban_active.to_string(),
        f2b_fmt,
    )?;
    current_row += 1;

    sheet.write_string_with_format(current_row, 0, "Auditd Active", &header_format())?;
    let audit_fmt = if report.security.auditd_active {
        &safe
    } else {
        &risky
    };
    sheet.write_string_with_format(
        current_row,
        1,
        report.security.auditd_active.to_string(),
        audit_fmt,
    )?;
    current_row += 1;

    if !report.host.failed_services.is_empty() {
        sheet.write_string_with_format(current_row, 0, "Failed Services", &header_format())?;
        sheet.write_string_with_format(
            current_row,
            1,
            report.host.failed_services.join(", "),
            &critical_band(current_row),
        )?;
        current_row += 1;
    }

    // NTP – always shown (fixed: use current_row, no data push)
    sheet.write_string_with_format(current_row, 0, "NTP Synchronized", &header_format())?;
    let ntp_value = match (report.host.ntp_synchronized, report.host.time_offset_ms) {
        (true, Some(ms)) => format!("yes ({:.1}ms offset)", ms),
        (true, None) => "yes".to_string(),
        (false, Some(ms)) => format!("no ({:.0}ms offset)", ms),
        (false, None) => "no".to_string(),
    };
    let ntp_fmt = if report.host.ntp_synchronized {
        ok_band(current_row)
    } else {
        critical_band(current_row)
    };
    sheet.write_string_with_format(current_row, 1, &ntp_value, &ntp_fmt)?;
    current_row += 1;

    if !report.security.sudo_nopasswd_entries.is_empty() {
        sheet.write_string_with_format(current_row, 0, "Sudo NOPASSWD", &header_format())?;
        sheet.write_string_with_format(
            current_row,
            1,
            report.security.sudo_nopasswd_entries.join("; "),
            &critical_band(current_row),
        )?;
        current_row += 1;
    }
    if let Some(mode) = report.security.sudoers_mode {
        sheet.write_string_with_format(current_row, 0, "Sudoers Permissions", &header_format())?;
        let (text, fmt) = if mode != 0o440 {
            (
                format!("{:o} (expected 0440)", mode),
                critical_band(current_row),
            )
        } else {
            (format!("{:o}", mode), ok_band(current_row))
        };
        sheet.write_string_with_format(current_row, 1, &text, &fmt)?;
        current_row += 1;
    }

    if !report.security.sysctl_issues.is_empty() {
        sheet.write_string_with_format(current_row, 0, "Sysctl Issues", &header_format())?;
        sheet.write_string_with_format(
            current_row,
            1,
            report.security.sysctl_issues.join("; "),
            &critical_band(current_row),
        )?;
        current_row += 1;
    }

    current_row += 1;

    if !report.security.shell_users.is_empty() {
        write_headers_at(
            &mut sheet,
            current_row,
            &["User", "Last Login", "Last Remote SSH", "Authorized Keys"],
        )?;
        current_row += 1;
        for u in &report.security.shell_users {
            let band = row_band(current_row);
            sheet.write_string_with_format(current_row, 0, &u.username, &band)?;
            sheet.write_string_with_format(current_row, 1, &u.last_login, &band)?;
            sheet.write_string_with_format(current_row, 2, &u.last_ssh_login, &band)?;
            sheet.write_number_with_format(
                current_row,
                3,
                u.authorized_keys_count as f64,
                &num_fmt,
            )?;
            current_row += 1;
        }
        current_row += 1;
    }

    // ---------- Docker section ----------
    if report.topology.docker_active {
        sheet.write_string_with_format(current_row, 0, "Docker", &header_format())?;
        current_row += 1;

        sheet.write_string_with_format(current_row, 0, "Docker Active", &header_format())?;
        sheet.write_string_with_format(
            current_row,
            1,
            report.topology.docker_active.to_string(),
            &row_band(current_row),
        )?;
        current_row += 1;
        sheet.write_string_with_format(current_row, 0, "Total Images", &header_format())?;
        sheet.write_number_with_format(
            current_row,
            1,
            report.topology.images_count as f64,
            &num_fmt,
        )?;
        current_row += 1;
        sheet.write_string_with_format(current_row, 0, "Dangling Images", &header_format())?;
        sheet.write_number_with_format(
            current_row,
            1,
            report.topology.dangling_images_count as f64,
            &num_fmt,
        )?;
        current_row += 1;
        sheet.write_string_with_format(
            current_row,
            0,
            "Dangling Wasted Space (GB)",
            &header_format(),
        )?;
        sheet.write_number_with_format(
            current_row,
            1,
            report.topology.total_dangling_size_mb as f64 / 1024.0,
            &num_fmt,
        )?;
        current_row += 2;

        write_headers_at(
            &mut sheet,
            current_row,
            &[
                "Name",
                "Image",
                "State",
                "Status",
                "Size (GB)",
                "Log Size (GB)",
                "Mounts",
                "Security Issues",
            ],
        )?;
        current_row += 1;
        for c in &report.topology.containers {
            let band = row_band(current_row);
            sheet.write_string_with_format(current_row, 0, &c.name, &band)?;
            sheet.write_string_with_format(current_row, 1, &c.image, &band)?;
            sheet.write_string_with_format(current_row, 2, &c.state, &band)?;
            sheet.write_string_with_format(current_row, 3, &c.status, &band)?;
            sheet.write_number_with_format(current_row, 4, c.size_mb as f64 / 1024.0, &num_fmt)?;
            sheet.write_number_with_format(
                current_row,
                5,
                c.log_size_mb as f64 / 1024.0,
                &num_fmt,
            )?;
            sheet.write_string_with_format(current_row, 6, c.mounts.join(" | "), &band)?;

            let issue_list: Vec<&str> = c.security_issues();
            let issue_str = if issue_list.is_empty() {
                "-".to_string()
            } else {
                issue_list.join(", ")
            };
            if issue_str != "-" {
                sheet.write_string_with_format(
                    current_row,
                    7,
                    &issue_str,
                    &critical_band(current_row),
                )?;
            } else {
                sheet.write_string_with_format(current_row, 7, &issue_str, &band)?;
            }
            current_row += 1;
        }
        current_row += 1;
    }

    // ---------- Packages section ----------
    if report.packages.manager.is_known() {
        sheet.write_string_with_format(current_row, 0, "Packages", &header_format())?;
        current_row += 1;

        let manager_str = match report.packages.manager {
            PackageManager::Apt => "apt (Debian/Ubuntu)",
            PackageManager::Dnf => "dnf (Fedora/RHEL)",
            PackageManager::Yum => "yum (RHEL/CentOS)",
            PackageManager::Pacman => "pacman (Arch)",
            PackageManager::Zypper => "zypper (openSUSE/SLES)",
            PackageManager::Unknown => "Unknown",
        };
        sheet.write_string_with_format(current_row, 0, "Package Manager", &header_format())?;
        sheet.write_string_with_format(current_row, 1, manager_str, &row_band(current_row))?;
        current_row += 1;
        sheet.write_string_with_format(current_row, 0, "Installed Packages", &header_format())?;
        sheet.write_number_with_format(
            current_row,
            1,
            report.packages.installed_count as f64,
            &num_fmt,
        )?;
        current_row += 1;
        sheet.write_string_with_format(
            current_row,
            0,
            "Cache Freshly Refreshed",
            &header_format(),
        )?;
        sheet.write_string_with_format(
            current_row,
            1,
            report.packages.cache_refreshed.to_string(),
            &row_band(current_row),
        )?;
        current_row += 2;

        write_headers_at(
            &mut sheet,
            current_row,
            &["Package", "Current", "Available", "Security"],
        )?;
        current_row += 1;
        let mut sorted: Vec<_> = report.packages.upgradable.iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.is_security));
        for p in &sorted {
            let band = row_band(current_row);
            sheet.write_string_with_format(current_row, 0, &p.name, &band)?;
            sheet.write_string_with_format(current_row, 1, &p.current_version, &band)?;
            sheet.write_string_with_format(current_row, 2, &p.new_version, &band)?;
            if p.is_security {
                sheet.write_string_with_format(
                    current_row,
                    3,
                    "YES",
                    &critical_band(current_row),
                )?;
            } else {
                sheet.write_string_with_format(current_row, 3, "-", &band)?;
            }
            current_row += 1;
        }
    }

    sheet.set_column_width(0, 30.0)?;
    sheet.set_column_width(1, 50.0)?;
    sheet.set_column_width(2, 12.0)?;
    sheet.set_column_width(3, 12.0)?;

    Ok(sheet)
}

// =====================================================================
// Wrappers for single‑host report (backward compatible)
// =====================================================================

fn sheet_overview(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    sheet_overview_named(report, "Overview")
}

fn sheet_overview_named(
    report: &AgentReport,
    sheet_name: &str,
) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name(sheet_name)?;
    write_headers(&mut sheet, &["Field", "Value"])?;

    let backup_str = if report.host.backup_tools.is_empty() {
        "None (CRITICAL)".to_string()
    } else {
        report.host.backup_tools.join(", ")
    };

    let rows: Vec<(&str, String)> = vec![
        ("Risk Score", format!("{}/100", report.risk_score)),
        ("Scan ID", report.scan_id.clone()),
        ("Timestamp", report.timestamp.clone()),
        ("Ran as root", report.is_root_execution.to_string()),
        ("Hostname", report.host.hostname.clone()),
        ("Provider", report.host.hosting_provider.clone()),
        ("External IP", report.host.external_ipv4.clone()),
        ("OS", report.host.os_version.clone()),
        ("Kernel", report.host.kernel.clone()),
        ("Backup tools", backup_str),
        ("Uptime (days)", report.host.uptime_days.to_string()),
        ("Reboot required", report.host.reboot_required.to_string()),
        ("CPU cores", report.host.cpu_cores.to_string()),
        (
            "RAM total (GB)",
            format!("{:.2}", report.host.total_ram_mb as f64 / 1024.0),
        ),
        (
            "Swap total (GB)",
            format!("{:.2}", report.host.swap_total_mb as f64 / 1024.0),
        ),
        (
            "Load average",
            format!(
                "{:.2}, {:.2}, {:.2}",
                report.host.load_average.0, report.host.load_average.1, report.host.load_average.2
            ),
        ),
        ("OOM kills", report.host.oom_kills.to_string()),
        ("Zombie processes", report.host.zombie_processes.to_string()),
        (
            "Security modules (LSM)",
            report.host.security_modules.join(", "),
        ),
        ("Tech stack", report.host.tech_stack.join(", ")),
    ];

    for (i, (label, value)) in rows.iter().enumerate() {
        let row = (i + 1) as u32;
        let band = row_band(row);
        sheet.write_string_with_format(row, 0, *label, &band)?;
        if *label == "Risk Score" {
            let score_fmt = if report.risk_score >= 70 {
                critical_band(row)
            } else if report.risk_score >= 40 {
                warning_band(row)
            } else {
                ok_band(row)
            };
            sheet.write_string_with_format(row, 1, value, &score_fmt)?;
        } else if *label == "Backup tools" {
            let bk_fmt = if report.host.backup_tools.is_empty() {
                critical_band(row)
            } else {
                ok_band(row)
            };
            sheet.write_string_with_format(row, 1, value, &bk_fmt)?;
        } else {
            sheet.write_string_with_format(row, 1, value, &band)?;
        }
    }

    let branding_row = rows.len() as u32 + 2;
    let subtle = Format::new()
        .set_font_size(10)
        .set_font_color(Color::RGB(0x808080))
        .set_italic();

    sheet.write_formula_with_format(
        branding_row,
        0,
        r#"=HYPERLINK("https://owlzops.com", "Generated by Owlzops Mapper")"#,
        &subtle,
    )?;
    sheet.write_formula_with_format(
        branding_row + 1,
        0,
        r#"=HYPERLINK("mailto:hello@owlzops.com", "Need help with server audit or migration? Contact us: hello@owlzops.com")"#,
        &subtle,
    )?;

    let start = branding_row + 3;
    sheet.write_string_with_format(start, 0, "Top Memory Processes", &header_format())?;
    sheet.write_string_with_format(start, 1, "PID", &header_format())?;
    sheet.write_string_with_format(start, 2, "RAM (MB)", &header_format())?;
    for (i, p) in report.host.top_memory_processes.iter().enumerate() {
        let row = start + 1 + i as u32;
        let band = row_band(row);
        sheet.write_string_with_format(row, 0, &p.name, &band)?;
        sheet.write_number_with_format(row, 1, p.pid as f64, &number_format())?;
        sheet.write_number_with_format(row, 2, p.memory_mb as f64, &number_format())?;
    }

    let mut data: Vec<Vec<String>> = vec![vec!["Field".to_string(), "Value".to_string()]];
    for (label, value) in &rows {
        data.push(vec![label.to_string(), value.clone()]);
    }
    auto_fit_columns(&mut sheet, &data, &[12.0, 12.0])?;

    Ok(sheet)
}

fn sheet_storage(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Storage")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);

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
        let band = fmts.row_band(w.current_row());

        w.write_string(0, &disk.mount_point, band)?;
        w.write_number(1, disk.total_gb as f64, &fmts.number)?;
        w.write_number(2, disk.used_gb as f64, &fmts.number)?;

        let usage_fmt = if usage_pct > 90.0 {
            fmts.critical_band(w.current_row())
        } else if usage_pct > 75.0 {
            fmts.warning_band(w.current_row())
        } else {
            fmts.ok_band(w.current_row())
        };
        w.write_number(3, usage_pct, usage_fmt)?;

        let inode_str = disk
            .inode_usage_percent
            .clone()
            .unwrap_or_else(|| "-".to_string());
        w.write_string(4, &inode_str, band)?;

        w.next_row();
    }

    w.apply_col_widths_with_min(&[12.0, 10.0, 10.0, 10.0, 10.0])?;
    Ok(sheet)
}

fn sheet_databases(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    sheet_databases_named(report, "Databases")
}

fn sheet_databases_named(
    report: &AgentReport,
    sheet_name: &str,
) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name(sheet_name)?;

    write_headers(
        &mut sheet,
        &["Engine", "Version", "Data Directory", "Size (GB)"],
    )?;

    let num_fmt = number_format();
    let mut data: Vec<Vec<String>> = vec![vec![
        "Engine".to_string(),
        "Version".to_string(),
        "Data Directory".to_string(),
        "Size (GB)".to_string(),
    ]];

    for (i, db) in report.databases.iter().enumerate() {
        let row = (i + 1) as u32;
        let band = row_band(row);
        sheet.write_string_with_format(row, 0, &db.engine, &band)?;
        sheet.write_string_with_format(row, 1, &db.version, &band)?;
        sheet.write_string_with_format(row, 2, &db.data_dir, &band)?;
        sheet.write_number_with_format(row, 3, db.size_mb as f64 / 1024.0, &num_fmt)?;

        data.push(vec![
            db.engine.clone(),
            db.version.clone(),
            db.data_dir.clone(),
            format!("{:.2}", db.size_mb as f64 / 1024.0),
        ]);
    }

    if !report.databases.is_empty() {
        let total_row = report.databases.len() as u32 + 2;
        let total_gb: f64 = report
            .databases
            .iter()
            .map(|d| d.size_mb as f64 / 1024.0)
            .sum();
        sheet.write_string_with_format(total_row, 2, "Total", &header_format())?;
        sheet.write_number_with_format(total_row, 3, total_gb, &num_fmt)?;

        data.push(vec![
            String::new(),
            String::new(),
            "Total".to_string(),
            format!("{:.2}", total_gb),
        ]);
    }

    auto_fit_columns(&mut sheet, &data, &[10.0, 20.0, 20.0, 10.0])?;
    Ok(sheet)
}

fn sheet_network(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    sheet_network_named(report, "Network")
}

fn sheet_network_named(
    report: &AgentReport,
    sheet_name: &str,
) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name(sheet_name)?;

    sheet.write_string_with_format(0, 0, "Firewall Active", &header_format())?;
    sheet.write_string_with_format(
        0,
        1,
        report.network.firewall_active.to_string(),
        &row_band(0),
    )?;
    sheet.write_string_with_format(1, 0, "DNS Resolvers", &header_format())?;
    sheet.write_string_with_format(1, 1, report.network.dns_resolvers.join(", "), &row_band(1))?;

    let mut data = vec![
        vec![
            "Firewall Active".to_string(),
            report.network.firewall_active.to_string(),
        ],
        vec![
            "DNS Resolvers".to_string(),
            report.network.dns_resolvers.join(", "),
        ],
    ];

    let port_start = 3u32;
    write_headers_at(
        &mut sheet,
        port_start,
        &["Protocol", "Port", "Process", "Bind Address"],
    )?;
    for (i, p) in report.network.listening_ports.iter().enumerate() {
        let row = port_start + 1 + i as u32;
        let band = row_band(row);

        sheet.write_string_with_format(row, 0, &p.protocol, &band)?;
        sheet.write_string_with_format(row, 1, &p.port, &band)?;
        sheet.write_string_with_format(row, 2, &p.process, &band)?;
        let addr_fmt = if p.bind_address == "0.0.0.0" || p.bind_address == "::" {
            critical_band(row)
        } else {
            ok_band(row)
        };
        sheet.write_string_with_format(row, 3, &p.bind_address, &addr_fmt)?;

        data.push(vec![
            p.protocol.clone(),
            p.port.clone(),
            p.process.clone(),
            p.bind_address.clone(),
        ]);
    }

    let ssl_start = port_start + report.network.listening_ports.len() as u32 + 3;
    write_headers_at(&mut sheet, ssl_start, &["Domain", "Expires", "Days Left"])?;
    for (i, cert) in report.network.ssl_certificates.iter().enumerate() {
        let row = ssl_start + 1 + i as u32;
        let band = row_band(row);
        sheet.write_string_with_format(row, 0, &cert.domain, &band)?;
        sheet.write_string_with_format(row, 1, &cert.expiry_date, &band)?;
        match cert.days_remaining {
            Some(d) if cert.is_critical => {
                sheet.write_number_with_format(row, 2, d as f64, &critical_band(row))?
            }
            Some(d) if cert.is_warning => {
                sheet.write_number_with_format(row, 2, d as f64, &warning_band(row))?
            }
            Some(d) => sheet.write_number_with_format(row, 2, d as f64, &ok_band(row))?,
            None => sheet.write_string_with_format(row, 2, "unknown", &band)?,
        };

        data.push(vec![
            cert.domain.clone(),
            cert.expiry_date.clone(),
            cert.days_remaining
                .map(|d| d.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            String::new(),
        ]);
    }

    let hosts_start = ssl_start + report.network.ssl_certificates.len() as u32 + 3;
    sheet.write_string_with_format(
        hosts_start,
        0,
        "Custom /etc/hosts Overrides",
        &header_format(),
    )?;
    for (i, h) in report.network.custom_host_overrides.iter().enumerate() {
        let row = hosts_start + 1 + i as u32;
        let band = row_band(row);
        sheet.write_string_with_format(row, 0, h, &band)?;
        data.push(vec![h.clone(), String::new(), String::new(), String::new()]);
    }

    auto_fit_columns(&mut sheet, &data, &[12.0, 12.0, 12.0, 12.0])?;
    Ok(sheet)
}

fn sheet_security(report: &AgentReport, fmts: &Formats) -> Result<Worksheet, XlsxError> {
    let mut sheet = Worksheet::new();
    sheet.set_name("Security")?;
    let mut w = SheetWriter::new(&mut sheet, fmts);

    // SSH Password Auth
    let pa_fmt = if report.security.ssh_password_auth_enabled {
        Some(&fmts.critical)
    } else {
        Some(&fmts.ok)
    };
    w.write_kv_row(
        "SSH Password Auth Enabled",
        &report.security.ssh_password_auth_enabled.to_string(),
        pa_fmt,
    )?;

    // SSH Root Login
    let rl_fmt = if report.security.ssh_root_login_enabled {
        Some(&fmts.critical)
    } else {
        Some(&fmts.ok)
    };
    w.write_kv_row(
        "SSH Root Login Enabled",
        &report.security.ssh_root_login_enabled.to_string(),
        rl_fmt,
    )?;

    // SSH Config Source
    w.write_kv_row(
        "SSH Config Source",
        &report.security.ssh_config_source,
        None,
    )?;

    // Fail2Ban Active
    let f2b_fmt = if report.security.fail2ban_active {
        Some(&fmts.ok)
    } else {
        Some(&fmts.critical)
    };
    w.write_kv_row(
        "Fail2Ban Active",
        &report.security.fail2ban_active.to_string(),
        f2b_fmt,
    )?;

    // Auditd Active
    let audit_fmt = if report.security.auditd_active {
        Some(&fmts.ok)
    } else {
        Some(&fmts.critical)
    };
    w.write_kv_row(
        "Auditd Active",
        &report.security.auditd_active.to_string(),
        audit_fmt,
    )?;

    // Failed Services
    if !report.host.failed_services.is_empty() {
        w.write_kv_row(
            "Failed Services",
            &report.host.failed_services.join(", "),
            Some(fmts.critical_band(w.current_row())),
        )?;
    }

    // NTP
    let ntp_value = match (report.host.ntp_synchronized, report.host.time_offset_ms) {
        (true, Some(ms)) => format!("yes ({:.1}ms offset)", ms),
        (true, None) => "yes".to_string(),
        (false, Some(ms)) => format!("no ({:.0}ms offset)", ms),
        (false, None) => "no".to_string(),
    };
    let ntp_fmt = if report.host.ntp_synchronized {
        Some(fmts.ok_band(w.current_row()))
    } else {
        Some(fmts.critical_band(w.current_row()))
    };
    w.write_kv_row("NTP Synchronized", &ntp_value, ntp_fmt)?;

    // Sudo NOPASSWD
    if !report.security.sudo_nopasswd_entries.is_empty() {
        w.write_kv_row(
            "Sudo NOPASSWD",
            &report.security.sudo_nopasswd_entries.join("; "),
            Some(fmts.critical_band(w.current_row())),
        )?;
    }

    // Sudoers Permissions
    if let Some(mode) = report.security.sudoers_mode {
        let (text, fmt) = if mode != 0o440 {
            (
                format!("{:o} (expected 0440)", mode),
                Some(fmts.critical_band(w.current_row())),
            )
        } else {
            (format!("{:o}", mode), Some(fmts.ok_band(w.current_row())))
        };
        w.write_kv_row("Sudoers Permissions", &text, fmt)?;
    }

    // Sysctl Issues
    if !report.security.sysctl_issues.is_empty() {
        w.write_kv_row(
            "Sysctl Issues",
            &report.security.sysctl_issues.join("; "),
            Some(fmts.critical_band(w.current_row())),
        )?;
    }

    // Shell Users table
    if !report.security.shell_users.is_empty() {
        w.next_row(); // blank line before table
        w.write_header(&["User", "Last Login", "Last Remote SSH", "Authorized Keys"])?;
        for u in &report.security.shell_users {
            let band = fmts.row_band(w.current_row());
            w.write_string(0, &u.username, band)?;
            w.write_string(1, &u.last_login, band)?;
            w.write_string(2, &u.last_ssh_login, band)?;
            w.write_number(3, u.authorized_keys_count as f64, &fmts.number)?;
            w.next_row();
        }
    }

    w.apply_col_widths_with_min(&[12.0, 12.0, 12.0, 10.0])?;
    Ok(sheet)
}

fn sheet_docker(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    sheet_docker_named(report, "Docker")
}

fn sheet_docker_named(
    report: &AgentReport,
    sheet_name: &str,
) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name(sheet_name)?;

    sheet.write_string_with_format(0, 0, "Docker Active", &header_format())?;
    sheet.write_string_with_format(
        0,
        1,
        report.topology.docker_active.to_string(),
        &row_band(0),
    )?;
    sheet.write_string_with_format(1, 0, "Total Images", &header_format())?;
    sheet.write_number_with_format(1, 1, report.topology.images_count as f64, &number_format())?;
    sheet.write_string_with_format(2, 0, "Dangling Images", &header_format())?;
    sheet.write_number_with_format(
        2,
        1,
        report.topology.dangling_images_count as f64,
        &number_format(),
    )?;
    sheet.write_string_with_format(3, 0, "Dangling Wasted Space (GB)", &header_format())?;
    sheet.write_number_with_format(
        3,
        1,
        report.topology.total_dangling_size_mb as f64 / 1024.0,
        &number_format(),
    )?;

    let mut data = vec![
        vec![
            "Docker Active".to_string(),
            report.topology.docker_active.to_string(),
        ],
        vec![
            "Total Images".to_string(),
            report.topology.images_count.to_string(),
        ],
        vec![
            "Dangling Images".to_string(),
            report.topology.dangling_images_count.to_string(),
        ],
        vec![
            "Dangling Wasted Space (GB)".to_string(),
            format!(
                "{:.2}",
                report.topology.total_dangling_size_mb as f64 / 1024.0
            ),
        ],
    ];

    let containers_start = 5u32;
    write_headers_at(
        &mut sheet,
        containers_start,
        &[
            "Name",
            "Image",
            "State",
            "Status",
            "Size (GB)",
            "Log Size (GB)",
            "Mounts",
            "Security Issues",
        ],
    )?;
    for (i, c) in report.topology.containers.iter().enumerate() {
        let row = containers_start + 1 + i as u32;
        let band = row_band(row);
        sheet.write_string_with_format(row, 0, &c.name, &band)?;
        sheet.write_string_with_format(row, 1, &c.image, &band)?;
        sheet.write_string_with_format(row, 2, &c.state, &band)?;
        sheet.write_string_with_format(row, 3, &c.status, &band)?;
        sheet.write_number_with_format(row, 4, c.size_mb as f64 / 1024.0, &number_format())?;
        sheet.write_number_with_format(row, 5, c.log_size_mb as f64 / 1024.0, &number_format())?;
        sheet.write_string_with_format(row, 6, c.mounts.join(" | "), &band)?;

        let issues = c.security_issues();
        let issue_str = if issues.is_empty() {
            "-".to_string()
        } else {
            issues.join(", ")
        };
        if issue_str != "-" {
            sheet.write_string_with_format(row, 7, &issue_str, &critical_band(row))?;
        } else {
            sheet.write_string_with_format(row, 7, &issue_str, &band)?;
        }

        data.push(vec![
            c.name.clone(),
            c.image.clone(),
            c.state.clone(),
            c.status.clone(),
            format!("{:.2}", c.size_mb as f64 / 1024.0),
            format!("{:.2}", c.log_size_mb as f64 / 1024.0),
            c.mounts.join(" | "),
            issue_str,
        ]);
    }

    auto_fit_columns(
        &mut sheet,
        &data,
        &[12.0, 12.0, 8.0, 12.0, 10.0, 10.0, 20.0, 12.0],
    )?;
    Ok(sheet)
}

fn sheet_packages(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    sheet_packages_named(report, "Packages")
}

fn sheet_packages_named(
    report: &AgentReport,
    sheet_name: &str,
) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name(sheet_name)?;

    let manager_str = match report.packages.manager {
        PackageManager::Apt => "apt (Debian/Ubuntu)",
        PackageManager::Dnf => "dnf (Fedora/RHEL)",
        PackageManager::Yum => "yum (RHEL/CentOS)",
        PackageManager::Pacman => "pacman (Arch)",
        PackageManager::Zypper => "zypper (openSUSE/SLES)",
        PackageManager::Unknown => "Unknown",
    };
    sheet.write_string_with_format(0, 0, "Package Manager", &header_format())?;
    sheet.write_string_with_format(0, 1, manager_str, &row_band(0))?;
    sheet.write_string_with_format(1, 0, "Installed Packages", &header_format())?;
    sheet.write_number_with_format(
        1,
        1,
        report.packages.installed_count as f64,
        &number_format(),
    )?;
    sheet.write_string_with_format(2, 0, "Cache Freshly Refreshed", &header_format())?;
    sheet.write_string_with_format(
        2,
        1,
        report.packages.cache_refreshed.to_string(),
        &row_band(2),
    )?;

    let mut data = vec![
        vec!["Package Manager".to_string(), manager_str.to_string()],
        vec![
            "Installed Packages".to_string(),
            report.packages.installed_count.to_string(),
        ],
        vec![
            "Cache Freshly Refreshed".to_string(),
            report.packages.cache_refreshed.to_string(),
        ],
    ];

    let upg_start = 4u32;
    write_headers_at(
        &mut sheet,
        upg_start,
        &["Package", "Current", "Available", "Security"],
    )?;
    let mut sorted: Vec<_> = report.packages.upgradable.iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.is_security));
    for (i, p) in sorted.iter().enumerate() {
        let row = upg_start + 1 + i as u32;
        let band = row_band(row);
        sheet.write_string_with_format(row, 0, &p.name, &band)?;
        sheet.write_string_with_format(row, 1, &p.current_version, &band)?;
        sheet.write_string_with_format(row, 2, &p.new_version, &band)?;
        if p.is_security {
            sheet.write_string_with_format(row, 3, "YES", &critical_band(row))?;
        } else {
            sheet.write_string_with_format(row, 3, "-", &band)?;
        }

        data.push(vec![
            p.name.clone(),
            p.current_version.clone(),
            p.new_version.clone(),
            if p.is_security {
                "YES".to_string()
            } else {
                "-".to_string()
            },
        ]);
    }

    auto_fit_columns(&mut sheet, &data, &[12.0, 12.0, 12.0, 10.0])?;
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
    )?);
    workbook.push_worksheet(sheet_overview(report)?);
    workbook.push_worksheet(sheet_storage(report, &fmts)?);
    workbook.push_worksheet(sheet_databases(report)?);
    workbook.push_worksheet(sheet_network(report)?);
    workbook.push_worksheet(sheet_security(report, &fmts)?);
    workbook.push_worksheet(sheet_docker(report)?);
    workbook.push_worksheet(sheet_packages(report)?);

    workbook.save(path)?;
    Ok(())
}

// =====================================================================
// WRITE MULTI-HOST REPORT
// =====================================================================
pub fn write_multi_host_report(reports: &[AgentReport], path: &str) -> Result<(), XlsxError> {
    let mut workbook = Workbook::new();

    workbook.push_worksheet(sheet_executive_summary(reports, true)?);

    for report in reports {
        let name = sanitize_sheet_name(&report.host.hostname, "Overview");
        workbook.push_worksheet(sheet_host_combined(report, &name)?);
    }

    workbook.save(path)?;
    Ok(())
}

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
        sheet.write(row, 0, &change.field)?;
        sheet.write(row, 1, change.before.as_deref().unwrap_or("-"))?;
        sheet.write(row, 2, change.after.as_deref().unwrap_or("-"))?;

        let (sev_text, fmt) = match change.severity {
            Severity::Improved => ("Improved", &green),
            Severity::Degraded => ("Degraded", &red),
            Severity::Changed => ("Changed", &yellow),
        };
        sheet.write_with_format(row, 3, sev_text, fmt)?;
    }

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
            sheet.write(row, 0, &mh.hostname)?;
            sheet.write(row, 1, &change.field)?;
            sheet.write(row, 2, change.before.as_deref().unwrap_or("-"))?;
            sheet.write(row, 3, change.after.as_deref().unwrap_or("-"))?;
            let (sev_text, fmt) = match change.severity {
                Severity::Improved => ("Improved", &green),
                Severity::Degraded => ("Degraded", &red),
                Severity::Changed => ("Changed", &yellow),
            };
            sheet.write_with_format(row, 4, sev_text, fmt)?;
            row += 1;
        }
    }

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
        let result = write_report(&report, tmp.to_str().unwrap());
        assert!(result.is_ok());
        assert!(tmp.exists());
        let metadata = std::fs::metadata(&tmp).unwrap();
        assert!(metadata.len() > 0);
        let _ = std::fs::remove_file(&tmp);
    }
}
