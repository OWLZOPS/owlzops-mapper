use crate::models::{AgentReport, PackageManager};
use rust_xlsxwriter::{Color, Format, FormatAlign, Workbook, XlsxError};

fn header_format() -> Format {
    Format::new()
        .set_bold()
        .set_background_color(Color::RGB(0x1F4E78))
        .set_font_color(Color::White)
        .set_align(FormatAlign::Left)
}

fn critical_format() -> Format {
    Format::new()
        .set_font_color(Color::RGB(0xC00000))
        .set_bold()
}

fn warning_format() -> Format {
    Format::new().set_font_color(Color::RGB(0xBF8F00))
}

fn ok_format() -> Format {
    Format::new().set_font_color(Color::RGB(0x375623))
}

fn number_format() -> Format {
    Format::new().set_num_format("0.00")
}

/// Writes the header row starting at row 0 and sets minimum column widths.
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

/// Same as `write_headers` but starting from an arbitrary row —
/// needed for sheets where multiple tables are stacked under a single heading.
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

fn sheet_overview(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name("Overview")?;
    write_headers(&mut sheet, &["Field", "Value"])?;

    let rows: Vec<(&str, String)> = vec![
        ("Scan ID", report.scan_id.clone()),
        ("Timestamp", report.timestamp.clone()),
        ("Ran as root", report.is_root_execution.to_string()),
        ("Hostname", report.host.hostname.clone()),
        ("Provider", report.host.hosting_provider.clone()),
        ("External IP", report.host.external_ipv4.clone()),
        ("OS", report.host.os_version.clone()),
        ("Kernel", report.host.kernel.clone()),
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
        sheet.write_string(row, 0, *label)?;
        sheet.write_string(row, 1, value)?;
    }

    // Top 5 memory-consuming processes in a separate block below.
    let start = rows.len() as u32 + 3;
    sheet.write_string_with_format(start, 0, "Top Memory Processes", &header_format())?;
    sheet.write_string_with_format(start, 1, "PID", &header_format())?;
    sheet.write_string_with_format(start, 2, "RAM (MB)", &header_format())?;
    for (i, p) in report.host.top_memory_processes.iter().enumerate() {
        let row = start + 1 + i as u32;
        sheet.write_string(row, 0, &p.name)?;
        sheet.write_number(row, 1, p.pid as f64)?;
        sheet.write_number(row, 2, p.memory_mb as f64)?;
    }

    Ok(sheet)
}

fn sheet_storage(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name("Storage")?;

    write_headers(
        &mut sheet,
        &[
            "Mount Point",
            "Total (GB)",
            "Used (GB)",
            "Usage %",
            "Inodes %",
        ],
    )?;

    let critical = critical_format();
    let warning = warning_format();
    let ok = ok_format();
    let num_fmt = number_format();

    let mut row = 1u32;
    for disk in &report.storage.disks {
        if disk.total_gb == 0 {
            continue;
        }
        let usage_pct = (disk.used_gb as f64 / disk.total_gb as f64) * 100.0;

        sheet.write_string(row, 0, &disk.mount_point)?;
        sheet.write_number_with_format(row, 1, disk.total_gb as f64, &num_fmt)?;
        sheet.write_number_with_format(row, 2, disk.used_gb as f64, &num_fmt)?;

        let usage_fmt = if usage_pct > 90.0 {
            &critical
        } else if usage_pct > 75.0 {
            &warning
        } else {
            &ok
        };
        sheet.write_number_with_format(row, 3, usage_pct, usage_fmt)?;

        let inode_str = disk
            .inode_usage_percent
            .clone()
            .unwrap_or_else(|| "-".to_string());
        sheet.write_string(row, 4, &inode_str)?;

        row += 1;
    }

    sheet.set_column_width(0, 28.0)?;
    sheet.set_column_width(1, 14.0)?;
    sheet.set_column_width(2, 14.0)?;
    sheet.set_column_width(3, 14.0)?;
    sheet.set_column_width(4, 14.0)?;
    Ok(sheet)
}

fn sheet_databases(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name("Databases")?;

    write_headers(
        &mut sheet,
        &["Engine", "Version", "Data Directory", "Size (GB)"],
    )?;

    let num_fmt = number_format();

    for (i, db) in report.databases.iter().enumerate() {
        let row = (i + 1) as u32;
        sheet.write_string(row, 0, &db.engine)?;
        sheet.write_string(row, 1, &db.version)?;
        sheet.write_string(row, 2, &db.data_dir)?;
        sheet.write_number_with_format(row, 3, db.size_mb as f64 / 1024.0, &num_fmt)?;
    }

    // Totals row
    if !report.databases.is_empty() {
        let total_row = report.databases.len() as u32 + 2;
        let total_gb: f64 = report
            .databases
            .iter()
            .map(|d| d.size_mb as f64 / 1024.0)
            .sum();
        sheet.write_string_with_format(total_row, 2, "Total", &header_format())?;
        sheet.write_number_with_format(total_row, 3, total_gb, &num_fmt)?;
    }

    sheet.set_column_width(0, 18.0)?;
    sheet.set_column_width(1, 32.0)?;
    sheet.set_column_width(2, 30.0)?;
    sheet.set_column_width(3, 14.0)?;
    Ok(sheet)
}

fn sheet_network(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name("Network")?;

    sheet.write_string_with_format(0, 0, "Firewall Active", &header_format())?;
    sheet.write_string(0, 1, &report.network.firewall_active.to_string())?;
    sheet.write_string_with_format(1, 0, "DNS Resolvers", &header_format())?;
    sheet.write_string(1, 1, &report.network.dns_resolvers.join(", "))?;

    // Listening ports
    let port_start = 3u32;
    write_headers_at(&mut sheet, port_start, &["Protocol", "Port", "Process"])?;
    for (i, p) in report.network.listening_ports.iter().enumerate() {
        let row = port_start + 1 + i as u32;
        sheet.write_string(row, 0, &p.protocol)?;
        sheet.write_string(row, 1, &p.port)?;
        sheet.write_string(row, 2, &p.process)?;
    }

    // SSL certificates
    let ssl_start = port_start + report.network.listening_ports.len() as u32 + 3;
    write_headers_at(&mut sheet, ssl_start, &["Domain", "Expires", "Days Left"])?;
    let critical = critical_format();
    let warning = warning_format();
    let ok = ok_format();
    for (i, cert) in report.network.ssl_certificates.iter().enumerate() {
        let row = ssl_start + 1 + i as u32;
        sheet.write_string(row, 0, &cert.domain)?;
        sheet.write_string(row, 1, &cert.expiry_date)?;
        match cert.days_remaining {
            Some(d) if cert.is_critical => {
                sheet.write_number_with_format(row, 2, d as f64, &critical)?
            }
            Some(d) if cert.is_warning => {
                sheet.write_number_with_format(row, 2, d as f64, &warning)?
            }
            Some(d) => sheet.write_number_with_format(row, 2, d as f64, &ok)?,
            None => sheet.write_string(row, 2, "unknown")?,
        };
    }

    // Custom /etc/hosts overrides
    let hosts_start = ssl_start + report.network.ssl_certificates.len() as u32 + 3;
    sheet.write_string_with_format(
        hosts_start,
        0,
        "Custom /etc/hosts Overrides",
        &header_format(),
    )?;
    for (i, h) in report.network.custom_host_overrides.iter().enumerate() {
        sheet.write_string(hosts_start + 1 + i as u32, 0, h)?;
    }

    sheet.set_column_width(0, 30.0)?;
    sheet.set_column_width(1, 30.0)?;
    sheet.set_column_width(2, 16.0)?;
    Ok(sheet)
}

fn sheet_security(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name("Security")?;

    let risky = critical_format();
    let safe = ok_format();

    sheet.write_string_with_format(0, 0, "SSH Password Auth Enabled", &header_format())?;
    let pa_fmt = if report.security.ssh_password_auth_enabled {
        &risky
    } else {
        &safe
    };
    sheet.write_string_with_format(
        0,
        1,
        &report.security.ssh_password_auth_enabled.to_string(),
        pa_fmt,
    )?;

    sheet.write_string_with_format(1, 0, "SSH Root Login Enabled", &header_format())?;
    let rl_fmt = if report.security.ssh_root_login_enabled {
        &risky
    } else {
        &safe
    };
    sheet.write_string_with_format(
        1,
        1,
        &report.security.ssh_root_login_enabled.to_string(),
        rl_fmt,
    )?;

    let users_start = 3u32;
    write_headers_at(
        &mut sheet,
        users_start,
        &["User", "Last Login", "Last Remote SSH", "Authorized Keys"],
    )?;
    for (i, u) in report.security.shell_users.iter().enumerate() {
        let row = users_start + 1 + i as u32;
        sheet.write_string(row, 0, &u.username)?;
        sheet.write_string(row, 1, &u.last_login)?;
        sheet.write_string(row, 2, &u.last_ssh_login)?;
        sheet.write_number(row, 3, u.authorized_keys_count as f64)?;
    }

    sheet.set_column_width(0, 18.0)?;
    sheet.set_column_width(1, 45.0)?;
    sheet.set_column_width(2, 30.0)?;
    sheet.set_column_width(3, 18.0)?;
    Ok(sheet)
}

fn sheet_docker(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name("Docker")?;

    sheet.write_string_with_format(0, 0, "Docker Active", &header_format())?;
    sheet.write_string(0, 1, &report.topology.docker_active.to_string())?;
    sheet.write_string_with_format(1, 0, "Total Images", &header_format())?;
    sheet.write_number(1, 1, report.topology.images_count as f64)?;
    sheet.write_string_with_format(2, 0, "Dangling Images", &header_format())?;
    sheet.write_number(2, 1, report.topology.dangling_images_count as f64)?;
    sheet.write_string_with_format(3, 0, "Dangling Wasted Space (GB)", &header_format())?;
    sheet.write_number(3, 1, report.topology.total_dangling_size_mb as f64 / 1024.0)?;

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
        ],
    )?;
    for (i, c) in report.topology.containers.iter().enumerate() {
        let row = containers_start + 1 + i as u32;
        sheet.write_string(row, 0, &c.name)?;
        sheet.write_string(row, 1, &c.image)?;
        sheet.write_string(row, 2, &c.state)?;
        sheet.write_string(row, 3, &c.status)?;
        sheet.write_number(row, 4, c.size_mb as f64 / 1024.0)?;
        sheet.write_number(row, 5, c.log_size_mb as f64 / 1024.0)?;
        sheet.write_string(row, 6, &c.mounts.join(" | "))?;
    }

    sheet.set_column_width(0, 22.0)?;
    sheet.set_column_width(1, 30.0)?;
    sheet.set_column_width(6, 60.0)?;
    Ok(sheet)
}

fn sheet_packages(report: &AgentReport) -> Result<rust_xlsxwriter::Worksheet, XlsxError> {
    let mut sheet = rust_xlsxwriter::Worksheet::new();
    sheet.set_name("Packages")?;

    let manager_str = match report.packages.manager {
        PackageManager::Apt => "apt (Debian/Ubuntu)",
        PackageManager::Dnf => "dnf (Fedora/RHEL)",
        PackageManager::Yum => "yum (RHEL/CentOS)",
        PackageManager::Pacman => "pacman (Arch)",
        PackageManager::Zypper => "zypper (openSUSE/SLES)",
        PackageManager::Unknown => "Unknown",
    };
    sheet.write_string_with_format(0, 0, "Package Manager", &header_format())?;
    sheet.write_string(0, 1, manager_str)?;
    sheet.write_string_with_format(1, 0, "Installed Packages", &header_format())?;
    sheet.write_number(1, 1, report.packages.installed_count as f64)?;
    sheet.write_string_with_format(2, 0, "Cache Freshly Refreshed", &header_format())?;
    sheet.write_string(2, 1, &report.packages.cache_refreshed.to_string())?;

    let upg_start = 4u32;
    write_headers_at(
        &mut sheet,
        upg_start,
        &["Package", "Current", "Available", "Security"],
    )?;
    let critical = critical_format();
    let mut sorted: Vec<_> = report.packages.upgradable.iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.is_security));
    for (i, p) in sorted.iter().enumerate() {
        let row = upg_start + 1 + i as u32;
        sheet.write_string(row, 0, &p.name)?;
        sheet.write_string(row, 1, &p.current_version)?;
        sheet.write_string(row, 2, &p.new_version)?;
        if p.is_security {
            sheet.write_string_with_format(row, 3, "YES", &critical)?;
        } else {
            sheet.write_string(row, 3, "-")?;
        }
    }

    sheet.set_column_width(0, 30.0)?;
    sheet.set_column_width(1, 18.0)?;
    sheet.set_column_width(2, 18.0)?;
    Ok(sheet)
}

/// Builds the complete xlsx report and saves it to the specified path.
/// Sheet order: Overview → Storage → Databases → Network → Security → Docker → Packages
pub fn write_report(report: &AgentReport, path: &str) -> Result<(), XlsxError> {
    let mut workbook = Workbook::new();

    workbook.push_worksheet(sheet_overview(report)?);
    workbook.push_worksheet(sheet_storage(report)?);
    workbook.push_worksheet(sheet_databases(report)?);
    workbook.push_worksheet(sheet_network(report)?);
    workbook.push_worksheet(sheet_security(report)?);
    workbook.push_worksheet(sheet_docker(report)?);
    workbook.push_worksheet(sheet_packages(report)?);

    workbook.save(path)?;
    Ok(())
}
