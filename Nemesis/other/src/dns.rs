use anyhow::Result;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::types::{Finding, ModuleResult, Severity, StageTimer};
use crate::ui;

/// SRV records to query for AD services.
const SRV_QUERIES: &[(&str, &str)] = &[
    ("_ldap._tcp.dc._msdcs", "Domain Controllers"),
    ("_kerberos._tcp", "Kerberos KDC"),
    ("_gc._tcp", "Global Catalog"),
    ("_kpasswd._tcp", "Kerberos Password Change"),
    ("_ldap._tcp.pdc._msdcs", "Primary DC"),
    ("_ldap._tcp.gc._msdcs", "GC (MSDCS)"),
    ("_kerberos._tcp.dc._msdcs", "KDC (MSDCS)"),
    ("_ldap._tcp.ForestDnsZones", "Forest DNS Zones"),
    ("_ldap._tcp.DomainDnsZones", "Domain DNS Zones"),
    ("_mssql._tcp", "MSSQL Server"),
];

/// Run DNS enumeration against the target.
pub async fn run(
    target: &str,
    domain: Option<&str>,
) -> Result<(ModuleResult, Option<String>)> {
    ui::section("DNS ENUMERATION");
    let timer = StageTimer::start();
    let spin = ui::spinner("DNS");
    let mut result = ModuleResult::new("dns");
    let mut discovered_domain: Option<String> = None;

    // Step 1: try reverse DNS to discover domain
    spin.set_message("reverse lookup...");
    if let Some(hostname) = discover_domain_from_target(target).await {
        ui::info(&format!("Reverse DNS: {} → {}", target, hostname));
        if let Some(dom) = domain_from_hostname(&hostname) {
            discovered_domain = Some(dom.clone());
            ui::success(&format!("Discovered domain: {}", dom));
        }
    }

    // Use provided domain or discovered domain
    let domain = domain
        .map(|d| d.to_string())
        .or_else(|| discovered_domain.clone());

    let Some(domain) = &domain else {
        ui::finish_spinner_warn(&spin, "no domain available for SRV queries");
        result = result.success(timer.elapsed());
        return Ok((result, discovered_domain));
    };

    // Step 2: create resolver pointing at target
    let resolver = build_resolver(target)?;

    // Step 3: SRV record queries
    spin.set_message("querying SRV records...");
    let mut total_records = 0u32;

    for (srv, label) in SRV_QUERIES {
        let fqdn = format!("{}.{}", srv, domain);
        match resolver.srv_lookup(&fqdn).await {
            Ok(lookup) => {
                let records: Vec<String> = lookup
                    .iter()
                    .map(|r| {
                        format!(
                            "{}:{} (priority={}, weight={})",
                            r.target(),
                            r.port(),
                            r.priority(),
                            r.weight()
                        )
                    })
                    .collect();
                total_records += records.len() as u32;
                if !records.is_empty() {
                    ui::kv(label, &records.join(", "));
                }
            }
            Err(_) => {}
        }
    }

    // Step 4: check for open recursion
    spin.set_message("checking open recursion...");
    if check_open_recursion(&resolver).await {
        let finding = Finding::new("dns", "DNS-001", Severity::Medium, "Open DNS recursion detected")
            .with_description("The DNS server resolves external queries, which may allow cache poisoning or information leakage")
            .with_recommendation("Disable recursive queries for external clients")
            .with_mitre("T1557");
        result.findings.push(finding);
        ui::warning("Open DNS recursion detected — external queries resolved");
    }

    // Step 5: attempt zone transfer
    spin.set_message("attempting zone transfer...");
    if let Ok(axfr_result) = attempt_zone_transfer(target, domain).await {
        if axfr_result {
            let finding = Finding::new(
                "dns",
                "DNS-002",
                Severity::High,
                "DNS zone transfer permitted",
            )
            .with_description("The DNS server allows zone transfers (AXFR), exposing all DNS records")
            .with_recommendation("Restrict zone transfers to authorized secondary DNS servers only")
            .with_mitre("T1590.002");
            result.findings.push(finding);
            ui::warning("Zone transfer (AXFR) appears to be permitted!");
        }
    }

    // Step 6: DNS dynamic update check
    spin.set_message("checking DNS dynamic updates...");
    if let Some(finding) = check_dns_dynamic_update(target, domain).await {
        result.findings.push(finding);
    }

    ui::finish_spinner(&spin, &format!("{} SRV records found", total_records));
    ui::stage_done("DNS", &format!("{} records", total_records), &timer.elapsed_pretty());

    result = result.success(timer.elapsed());
    Ok((result, discovered_domain))
}

/// Discover domain from target IP via reverse DNS.
pub async fn discover_domain_from_target(target: &str) -> Option<String> {
    let ip: IpAddr = target.parse().ok()?;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let lookup = tokio::time::timeout(Duration::from_secs(5), resolver.reverse_lookup(ip))
        .await
        .ok()?
        .ok()?;

    lookup
        .iter()
        .next()
        .map(|name| name.to_string().trim_end_matches('.').to_string())
}

/// Extract domain from FQDN hostname.
pub fn domain_from_hostname(hostname: &str) -> Option<String> {
    let parts: Vec<&str> = hostname.split('.').collect();
    if parts.len() >= 2 {
        Some(parts[1..].join("."))
    } else {
        None
    }
}

/// Build a resolver pointing at the target as DNS server.
fn build_resolver(target: &str) -> Result<TokioAsyncResolver> {
    let ip: IpAddr = target.parse()?;
    let ns = NameServerConfig::new(SocketAddr::new(ip, 53), Protocol::Udp);
    let mut config = ResolverConfig::new();
    config.add_name_server(ns);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    Ok(TokioAsyncResolver::tokio(config, opts))
}

/// Check if the DNS server resolves external queries (open recursion).
async fn check_open_recursion(resolver: &TokioAsyncResolver) -> bool {
    // Try to resolve an external domain — if it works, recursion is open
    let test_domains = ["www.google.com.", "www.cloudflare.com."];
    for domain in test_domains {
        if let Ok(lookup) = tokio::time::timeout(
            Duration::from_secs(3),
            resolver.lookup_ip(domain),
        )
        .await
        {
            if lookup.is_ok() {
                return true;
            }
        }
    }
    false
}

/// Attempt a DNS zone transfer using dig.
async fn attempt_zone_transfer(target: &str, domain: &str) -> Result<bool> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("dig")
            .args(["axfr", domain, &format!("@{}", target)])
            .output(),
    )
    .await??;

    let stdout = String::from_utf8_lossy(&output.stdout);
    ui::verbose_output("dig", &stdout);
    // If we get actual records back (not just SOA or error), transfer succeeded
    let record_count = stdout
        .lines()
        .filter(|l| !l.starts_with(';') && !l.is_empty() && l.contains('\t'))
        .count();

    Ok(record_count > 2) // More than just SOA records
}

/// Check if the DNS server accepts unauthenticated dynamic updates.
async fn check_dns_dynamic_update(target: &str, domain: &str) -> Option<Finding> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let test_name = format!("_aydee-dnstest-{}.{}", ts, domain);

    // nsupdate script: add a harmless TXT record, then immediately delete it
    let script = format!(
        "server {}\nzone {}\nupdate add {} 10 TXT \"aydee-dynamic-update-test\"\nsend\nupdate delete {} TXT\nsend\n",
        target, domain, test_name, test_name
    );

    let tmp_path = format!("/tmp/aydee_nsupdate_{}.txt", ts);
    if tokio::fs::write(&tmp_path, &script).await.is_err() {
        return None;
    }

    let out = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("nsupdate")
            .arg(&tmp_path)
            .output(),
    )
    .await;

    let _ = tokio::fs::remove_file(&tmp_path).await;

    match out {
        Ok(Ok(output)) => {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            ui::verbose_output("nsupdate", &combined);

            if output.status.success() {
                ui::warning("DNS dynamic updates allowed without authentication!");
                Some(
                    Finding::new(
                        "dns",
                        "DNS-003",
                        Severity::High,
                        "Unauthenticated DNS dynamic updates permitted",
                    )
                    .with_description(
                        "The DNS server accepts dynamic updates without authentication, allowing attackers to add/modify DNS records for MitM attacks",
                    )
                    .with_recommendation(
                        "Configure DNS zones to require secure dynamic updates only",
                    )
                    .with_mitre("T1557.001"),
                )
            } else {
                let lower = combined.to_lowercase();
                if lower.contains("refused") {
                    ui::info("DNS dynamic updates properly restricted");
                }
                None
            }
        }
        Ok(Err(_)) => {
            ui::verbose("nsupdate not found — skipping DNS dynamic update check");
            None
        }
        Err(_) => {
            ui::verbose("nsupdate timed out");
            None
        }
    }
}
