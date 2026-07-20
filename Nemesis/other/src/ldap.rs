use anyhow::Result;
use ldap3::controls::RawControl;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::time::Duration;

use crate::types::{DomainPasswordPolicy, Finding, LdapInfo, ModuleResult, Severity, StageTimer};
use crate::ui;

// ── Unauthenticated LDAP ────────────────────────────────────────────────────

/// Fingerprint via RootDSE (no bind required) and attempt anonymous enumeration.
pub async fn fingerprint(target: &str, port: u16) -> Result<(ModuleResult, LdapInfo)> {
    ui::section("LDAP FINGERPRINT");
    let timer = StageTimer::start();
    let spin = ui::spinner("LDAP");
    let mut result = ModuleResult::new("ldap-fingerprint");
    let mut info = LdapInfo::default();

    spin.set_message("querying RootDSE...");

    let url = if port == 636 || port == 3269 {
        format!("ldaps://{}:{}", target, port)
    } else {
        format!("ldap://{}:{}", target, port)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(10))
        .set_starttls(false);

    let (conn, mut ldap) = match tokio::time::timeout(
        Duration::from_secs(15),
        LdapConnAsync::with_settings(settings, &url),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            ui::finish_spinner_fail(&spin, &format!("connection failed: {}", e));
            result = result.failed(&e.to_string(), timer.elapsed());
            return Ok((result, info));
        }
        Err(_) => {
            ui::finish_spinner_fail(&spin, "connection timed out");
            result = result.failed("timeout", timer.elapsed());
            return Ok((result, info));
        }
    };

    tokio::spawn(async move { conn.drive().await });

    // Query RootDSE
    let rootdse = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["*"])
        .await
        .and_then(|r| r.success());

    match rootdse {
        Ok((rs, _res)) => {
            for entry in rs {
                let se = SearchEntry::construct(entry);
                // Extract key attributes
                if let Some(vals) = se.attrs.get("defaultNamingContext") {
                    if let Some(nc) = vals.first() {
                        info.naming_context = Some(nc.clone());
                        // Derive domain from DN
                        let domain = nc
                            .split(',')
                            .filter_map(|p| p.strip_prefix("DC=").or_else(|| p.strip_prefix("dc=")))
                            .collect::<Vec<_>>()
                            .join(".");
                        if !domain.is_empty() {
                            info.domain = Some(domain.clone());
                            ui::kv("Domain", &domain);
                        }
                        ui::kv("Naming Context", nc);
                    }
                }

                if let Some(vals) = se.attrs.get("dnsHostName") {
                    if let Some(h) = vals.first() {
                        info.dns_hostname = Some(h.clone());
                        ui::kv("DNS Hostname", h);
                    }
                }

                if let Some(vals) = se.attrs.get("domainFunctionality") {
                    if let Some(level) = vals.first() {
                        let label = functional_level_label(level);
                        info.functional_level = Some(label.to_string());
                        ui::kv("Domain Functional Level", label);
                    }
                }

                if let Some(vals) = se.attrs.get("forestFunctionality") {
                    if let Some(level) = vals.first() {
                        ui::kv("Forest Functional Level", functional_level_label(level));
                    }
                }

                // LDAP signing
                if let Some(vals) = se.attrs.get("supportedControl") {
                    let controls: Vec<&str> = vals.iter().map(|s| s.as_str()).collect();
                    if controls.contains(&"1.2.840.113556.1.4.473") {
                        ui::kv("Server-Side Sort", "supported");
                    }
                }

                if let Some(vals) = se.attrs.get("supportedSASLMechanisms") {
                    ui::kv("SASL Mechanisms", &vals.join(", "));
                }

                if let Some(vals) = se.attrs.get("isGlobalCatalogReady") {
                    if let Some(v) = vals.first() {
                        ui::kv("Global Catalog Ready", v);
                    }
                }
            }
        }
        Err(e) => {
            ui::finish_spinner_fail(&spin, &format!("RootDSE query failed: {}", e));
            let _ = ldap.unbind().await;
            result = result.failed(&e.to_string(), timer.elapsed());
            return Ok((result, info));
        }
    }

    // Check LDAP signing
    spin.set_message("checking LDAP signing...");
    check_ldap_signing(&mut result);

    ui::finish_spinner(&spin, "RootDSE enumerated");
    ui::stage_done(
        "LDAP FINGERPRINT",
        info.domain.as_deref().unwrap_or("unknown domain"),
        &timer.elapsed_pretty(),
    );

    let _ = ldap.unbind().await;
    result = result.success(timer.elapsed());
    Ok((result, info))
}

/// Run anonymous LDAP enumeration.
pub async fn run_anonymous(
    target: &str,
    port: u16,
    naming_context: Option<&str>,
) -> Result<ModuleResult> {
    ui::section("LDAP ANONYMOUS BIND");
    let timer = StageTimer::start();
    let spin = ui::spinner("LDAP-ANON");
    let mut result = ModuleResult::new("ldap-anonymous");

    let url = if port == 636 || port == 3269 {
        format!("ldaps://{}:{}", target, port)
    } else {
        format!("ldap://{}:{}", target, port)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(10));

    let (conn, mut ldap) = match tokio::time::timeout(
        Duration::from_secs(15),
        LdapConnAsync::with_settings(settings, &url),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        _ => {
            ui::finish_spinner_fail(&spin, "connection failed");
            result = result.failed("connection failed", timer.elapsed());
            return Ok(result);
        }
    };

    tokio::spawn(async move { conn.drive().await });

    // Attempt anonymous bind
    spin.set_message("attempting null bind...");
    match ldap.simple_bind("", "").await {
        Ok(res) if res.rc == 0 => {
            ui::success("Anonymous bind successful");
            let finding = Finding::new(
                "ldap",
                "LDAP-001",
                Severity::Medium,
                "LDAP anonymous bind permitted",
            )
            .with_description("Anonymous LDAP binding is allowed, enabling unauthenticated enumeration")
            .with_recommendation("Disable anonymous LDAP access unless explicitly required")
            .with_mitre("T1087.002");
            result.findings.push(finding);
        }
        _ => {
            ui::info("Anonymous bind rejected (expected)");
            let _ = ldap.unbind().await;
            ui::finish_spinner(&spin, "anonymous bind rejected");
            result = result.success(timer.elapsed());
            return Ok(result);
        }
    }

    // Try to enumerate users
    if let Some(base) = naming_context {
        spin.set_message("enumerating users...");
        match ldap
            .search(
                base,
                Scope::Subtree,
                "(&(objectClass=user)(objectCategory=person))",
                vec!["sAMAccountName"],
            )
            .await.and_then(|r| r.success())
        {
            Ok((rs, _)) => {
                for entry in rs {
                    let se = SearchEntry::construct(entry);
                    if let Some(names) = se.attrs.get("sAMAccountName") {
                        for n in names {
                            result.collected_users.push(n.clone());
                        }
                    }
                }
                if !result.collected_users.is_empty() {
                    ui::success(&format!(
                        "Enumerated {} users via anonymous bind",
                        result.collected_users.len()
                    ));
                }
            }
            Err(_) => {
                ui::info("User enumeration via anonymous bind not permitted");
            }
        }

        // Try domain policy
        spin.set_message("checking domain policy exposure...");
        match ldap
            .search(
                base,
                Scope::Base,
                "(objectClass=*)",
                vec![
                    "minPwdLength",
                    "maxPwdAge",
                    "lockoutThreshold",
                    "lockoutDuration",
                    "pwdHistoryLength",
                ],
            )
            .await.and_then(|r| r.success())
        {
            Ok((rs, _)) => {
                for entry in rs {
                    let se = SearchEntry::construct(entry);
                    let has_policy = !se.attrs.is_empty();
                    if has_policy {
                        ui::warning("Domain password policy readable via anonymous bind");
                        for (k, v) in &se.attrs {
                            ui::kv(k, &v.join(", "));
                        }
                        let finding = Finding::new(
                            "ldap",
                            "LDAP-002",
                            Severity::Low,
                            "Domain password policy exposed via anonymous bind",
                        )
                        .with_recommendation(
                            "Restrict password policy attributes from anonymous read access",
                        );
                        result.findings.push(finding);
                    }
                }
            }
            Err(_) => {}
        }
    }

    let _ = ldap.unbind().await;
    ui::finish_spinner(&spin, "anonymous enumeration complete");
    ui::stage_done("LDAP ANONYMOUS", "done", &timer.elapsed_pretty());
    result = result.success(timer.elapsed());
    Ok(result)
}

// ── Authenticated LDAP ──────────────────────────────────────────────────────

/// Run authenticated LDAP reconnaissance.
pub async fn run_authenticated(
    target: &str,
    port: u16,
    domain: &str,
    username: &str,
    password: &str,
    _ntlm: Option<&str>,
    naming_context: Option<&str>,
    tags: &[String],
) -> Result<ModuleResult> {
    ui::section("AUTHENTICATED LDAP RECON");
    let timer = StageTimer::start();
    let spin = ui::spinner("LDAP-AUTH");
    let mut result = ModuleResult::new("ldap-auth");

    let url = if port == 636 || port == 3269 {
        format!("ldaps://{}:{}", target, port)
    } else {
        format!("ldap://{}:{}", target, port)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(10));

    let (conn, mut ldap) = match tokio::time::timeout(
        Duration::from_secs(15),
        LdapConnAsync::with_settings(settings, &url),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        _ => {
            ui::finish_spinner_fail(&spin, "connection failed");
            result = result.failed("connection failed", timer.elapsed());
            return Ok(result);
        }
    };

    tokio::spawn(async move { conn.drive().await });

    // Bind with credentials — try multiple formats
    spin.set_message("authenticating...");
    let bind_dns = [
        format!("{}@{}", username, domain),                    // UPN
        format!("{}\\{}", domain.split('.').next().unwrap_or(domain), username), // Down-level
        username.to_string(),                                   // Plain
    ];

    let mut bound = false;
    for dn in &bind_dns {
        ui::verbose(&format!("LDAP bind attempt: {}", dn));
        match ldap.simple_bind(dn, password).await {
            Ok(res) if res.rc == 0 => {
                ui::success(&format!("Authenticated as {}", dn));
                bound = true;
                break;
            }
            Ok(res) => {
                ui::verbose(&format!("LDAP bind failed (rc={}): {}", res.rc, dn));
            }
            Err(e) => {
                ui::verbose(&format!("LDAP bind error: {} — {}", dn, e));
            }
        }
    }

    if !bound {
        ui::finish_spinner_fail(&spin, "authentication failed");
        result = result.failed("all bind attempts failed", timer.elapsed());
        let _ = ldap.unbind().await;
        return Ok(result);
    }

    let base = naming_context
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            domain
                .split('.')
                .map(|p| format!("DC={}", p))
                .collect::<Vec<_>>()
                .join(",")
        });

    let should_run = |tag: &str| -> bool {
        tags.is_empty() || tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    };

    // ── Collect users ───────────────────────────────────────────────────
    spin.set_message("collecting users...");
    match collect_usernames(&mut ldap, &base).await {
        Ok(users) => {
            ui::success(&format!("Collected {} users", users.len()));
            result.collected_users = users;
        }
        Err(e) => ui::warning(&format!("User collection failed: {}", e)),
    }

    // ── Domain password policy ──────────────────────────────────────────
    if should_run("policy") {
        spin.set_message("extracting domain password policy...");
        if let Some(policy) = collect_domain_password_policy(&mut ldap, &base).await {
            ui::info("Domain Password Policy:");
            ui::kv("  Min Password Length", &policy.min_pwd_length.to_string());
            ui::kv("  Lockout Threshold", &format!("{} attempts", policy.lockout_threshold));
            ui::kv("  Lockout Observation Window", &format!("{} min", policy.lockout_observation_window_min));
            ui::kv("  Lockout Duration", &format!("{} min", policy.lockout_duration_min));
            ui::kv("  Complexity Required", &policy.complexity_enabled.to_string());
            ui::kv("  Password History", &policy.pwd_history_length.to_string());
            if policy.lockout_threshold == 0 {
                ui::warning("No account lockout policy — spray freely");
                let finding = Finding::new(
                    "ldap", "POLICY-001", Severity::Medium,
                    "No account lockout threshold configured",
                )
                .with_description("The domain has no account lockout policy, allowing unlimited password attempts")
                .with_recommendation("Set lockoutThreshold to at least 5 and configure lockout duration")
                .with_mitre("T1110.003");
                result.findings.push(finding);
            }
            if policy.min_pwd_length < 8 {
                let finding = Finding::new(
                    "ldap", "POLICY-002", Severity::Medium,
                    &format!("Weak minimum password length: {}", policy.min_pwd_length),
                )
                .with_recommendation("Set minimum password length to at least 14 characters");
                result.findings.push(finding);
            }
            result.password_policy = Some(policy);
        }
    }

    // ── Kerberoastable SPNs ─────────────────────────────────────────────
    if should_run("kerberoast") {
        spin.set_message("checking Kerberoastable accounts...");
        collect_kerberoast(&mut ldap, &base, &mut result).await;
    }

    // ── AS-REP roastable ────────────────────────────────────────────────
    if should_run("asreproast") {
        spin.set_message("checking AS-REP roastable accounts...");
        collect_asrep_roastable(&mut ldap, &base, &mut result).await;
    }

    // ── Delegation ──────────────────────────────────────────────────────
    if should_run("delegation") {
        spin.set_message("checking delegation...");
        collect_delegation(&mut ldap, &base, &mut result).await;
    }

    // ── Machine Account Quota ───────────────────────────────────────────
    if should_run("maq") {
        spin.set_message("checking machine account quota...");
        collect_maq(&mut ldap, &base, &mut result).await;
    }

    // ── Trusts ──────────────────────────────────────────────────────────
    if should_run("trusts") {
        spin.set_message("enumerating trusts...");
        collect_trusts(&mut ldap, &base, &mut result).await;
    }

    // ── ADCS templates ──────────────────────────────────────────────────
    if should_run("adcs") {
        spin.set_message("checking AD CS templates...");
        collect_adcs_templates(&mut ldap, &base, &mut result).await;
    }

    // ── Obsolete computers ──────────────────────────────────────────────
    if should_run("computers") {
        spin.set_message("inventorying computers...");
        collect_computers(&mut ldap, &base, &mut result).await;
    }

    // ── Password policy ─────────────────────────────────────────────────
    if should_run("pso") {
        spin.set_message("checking password policies...");
        collect_password_policy(&mut ldap, &base, &mut result).await;
    }

    // ── DCSynC heuristics ───────────────────────────────────────────────
    if should_run("dcsync") {
        spin.set_message("checking replication rights...");
        collect_dcsync_heuristics(&mut ldap, &base, &mut result).await;
    }

    // ── LAPS ────────────────────────────────────────────────────────────
    if should_run("laps") {
        spin.set_message("checking LAPS...");
        collect_laps(&mut ldap, &base, &mut result).await;
    }

    // ── GPO inventory ───────────────────────────────────────────────────
    if should_run("gpo") {
        spin.set_message("enumerating GPOs...");
        collect_gpos(&mut ldap, &base, &mut result).await;
    }

    // ── Shadow Credentials ──────────────────────────────────────────────
    if should_run("shadow-creds") {
        spin.set_message("checking shadow credentials...");
        collect_shadow_credentials(&mut ldap, &base, &mut result).await;
    }

    // ── gMSA readability ──────────────────────────────────────────────
    if should_run("gmsa") {
        spin.set_message("checking gMSA readability...");
        collect_gmsa(&mut ldap, &base, &mut result).await;
    }

    // ── User descriptions (password hints) ──────────────────────────────
    if should_run("user-desc") {
        spin.set_message("checking user descriptions...");
        collect_user_descriptions(&mut ldap, &base, &mut result).await;
    }

    // ── Deleted but recoverable objects ─────────────────────────────────
    if should_run("deleted") {
        spin.set_message("checking deleted objects (Recycle Bin)...");
        collect_deleted_objects(&mut ldap, &base, &mut result).await;
    }

    // ── Pre-Windows 2000 Compatible Access ──────────────────────────────
    if should_run("pre2000") {
        spin.set_message("checking Pre-Windows 2000 group...");
        collect_pre2000_group(&mut ldap, &base, &mut result).await;
    }

    // ── Inactive / stale accounts ───────────────────────────────────────
    if should_run("inactive") {
        spin.set_message("checking inactive accounts...");
        collect_inactive_accounts(&mut ldap, &base, &mut result).await;
    }

    // ── Privileged group recursive membership ───────────────────────────
    if should_run("privgroups") {
        spin.set_message("enumerating privileged groups...");
        collect_privileged_groups(&mut ldap, &base, &mut result).await;
    }

    // ── AdminSDHolder ───────────────────────────────────────────────────
    if should_run("adminsdholder") {
        spin.set_message("checking AdminSDHolder...");
        collect_adminsdholder(&mut ldap, &base, &mut result).await;
    }

    // ── SID History ─────────────────────────────────────────────────────
    if should_run("sidhistory") {
        spin.set_message("checking SID history...");
        collect_sid_history(&mut ldap, &base, &mut result).await;
    }

    // ── Service account heuristics ──────────────────────────────────────
    if should_run("svc-accounts") {
        spin.set_message("identifying service accounts...");
        collect_service_accounts(&mut ldap, &base, &mut result).await;
    }

    let _ = ldap.unbind().await;

    let finding_count = result.findings.len();
    ui::finish_spinner(
        &spin,
        &format!(
            "{} findings, {} users collected",
            finding_count,
            result.collected_users.len()
        ),
    );
    ui::stage_done(
        "LDAP AUTH RECON",
        &format!("{} findings", finding_count),
        &timer.elapsed_pretty(),
    );

    result = result.success(timer.elapsed());
    Ok(result)
}

// ── Collection functions ────────────────────────────────────────────────────

async fn collect_usernames(ldap: &mut ldap3::Ldap, base: &str) -> Result<Vec<String>> {
    let (rs, _) = ldap
        .search(
            base,
            Scope::Subtree,
            "(&(objectClass=user)(objectCategory=person))",
            vec!["sAMAccountName"],
        )
        .await?
        .success()?;

    let mut users = Vec::new();
    for entry in rs {
        let se = SearchEntry::construct(entry);
        if let Some(names) = se.attrs.get("sAMAccountName") {
            users.extend(names.iter().cloned());
        }
    }
    Ok(users)
}

async fn collect_kerberoast(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))";
    let Ok((rs, _)) = ldap
        .search(base, Scope::Subtree, filter, vec!["sAMAccountName", "servicePrincipalName"])
        .await.and_then(|r| r.success())
    else {
        return;
    };

    let mut spn_users = Vec::new();
    for entry in rs {
        let se = SearchEntry::construct(entry);
        if let Some(names) = se.attrs.get("sAMAccountName") {
            if let Some(spns) = se.attrs.get("servicePrincipalName") {
                for name in names {
                    spn_users.push(format!("{} ({})", name, spns.join(", ")));
                }
            }
        }
    }

    if !spn_users.is_empty() {
        ui::warning(&format!("{} Kerberoastable account(s) found", spn_users.len()));
        for u in &spn_users {
            ui::kv("  SPN User", u);
        }
        let finding = Finding::new(
            "ldap",
            "KERB-001",
            Severity::High,
            &format!("{} Kerberoastable user account(s)", spn_users.len()),
        )
        .with_description("User accounts with SPNs can be Kerberoasted to crack their passwords offline")
        .with_evidence(&spn_users.join("\n"))
        .with_recommendation("Use managed service accounts (gMSA), rotate SPN account passwords frequently, and enforce strong passwords")
        .with_mitre("T1558.003");
        result.findings.push(finding);
    }
}

async fn collect_asrep_roastable(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    let Ok((rs, _)) = ldap
        .search(base, Scope::Subtree, filter, vec!["sAMAccountName"])
        .await.and_then(|r| r.success())
    else {
        return;
    };

    let mut users = Vec::new();
    for entry in rs {
        let se = SearchEntry::construct(entry);
        if let Some(names) = se.attrs.get("sAMAccountName") {
            users.extend(names.iter().cloned());
        }
    }

    if !users.is_empty() {
        ui::warning(&format!("{} AS-REP roastable account(s)", users.len()));
        for u in &users {
            ui::kv("  No Pre-Auth", u);
        }
        let finding = Finding::new(
            "ldap",
            "KERB-002",
            Severity::High,
            &format!("{} AS-REP roastable user account(s)", users.len()),
        )
        .with_description("Accounts with Kerberos pre-authentication disabled can be AS-REP roasted")
        .with_evidence(&users.join(", "))
        .with_recommendation("Enable Kerberos pre-authentication for all user accounts")
        .with_mitre("T1558.004");
        result.findings.push(finding);
    }
}

async fn collect_delegation(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    // Unconstrained delegation
    let filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))";
    if let Ok((rs, _)) = ldap
        .search(base, Scope::Subtree, filter, vec!["sAMAccountName", "dNSHostName"])
        .await.and_then(|r| r.success())
    {
        let hosts: Vec<String> = rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                se.attrs.get("sAMAccountName").and_then(|n| n.first().cloned())
            })
            .collect();

        if !hosts.is_empty() {
            ui::warning(&format!("{} host(s) with unconstrained delegation", hosts.len()));
            let finding = Finding::new(
                "ldap",
                "DELEG-001",
                Severity::Critical,
                &format!("Unconstrained delegation on {} host(s)", hosts.len()),
            )
            .with_description("Unconstrained delegation allows impersonation of any user who authenticates to the host")
            .with_evidence(&hosts.join(", "))
            .with_recommendation("Replace with constrained delegation or RBCD; monitor for TGT harvesting")
            .with_mitre("T1550.003");
            result.findings.push(finding);
        }
    }

    // Constrained delegation (msDS-AllowedToDelegateTo)
    let filter = "(msDS-AllowedToDelegateTo=*)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"],
        )
        .await
        .and_then(|r| r.success())
    {
        let mut constrained = Vec::new();
        let mut protocol_transition = Vec::new();

        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let delegates_to = se
                .attrs
                .get("msDS-AllowedToDelegateTo")
                .cloned()
                .unwrap_or_default();
            let uac: u32 = se
                .attrs
                .get("userAccountControl")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            let entry_str = format!("{} → {}", name, delegates_to.join(", "));

            // TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
            if uac & 0x1000000 != 0 {
                protocol_transition.push(entry_str);
            } else {
                constrained.push(entry_str);
            }
        }

        if !constrained.is_empty() {
            ui::info(&format!(
                "{} constrained delegation entries",
                constrained.len()
            ));
            for c in &constrained {
                ui::kv("  Constrained", c);
            }
        }

        if !protocol_transition.is_empty() {
            ui::warning(&format!(
                "{} constrained delegation with protocol transition (S4U2Self)",
                protocol_transition.len()
            ));
            for p in &protocol_transition {
                ui::kv("  Protocol Transition", p);
            }
            let finding = Finding::new(
                "ldap",
                "DELEG-002",
                Severity::High,
                &format!(
                    "{} account(s) with constrained delegation + protocol transition",
                    protocol_transition.len()
                ),
            )
            .with_description(
                "Accounts with TRUSTED_TO_AUTH_FOR_DELEGATION can perform S4U2Self to obtain tickets for any user, then S4U2Proxy to the allowed services — enabling impersonation without user interaction",
            )
            .with_evidence(&protocol_transition.join("\n"))
            .with_recommendation(
                "Remove TRUSTED_TO_AUTH_FOR_DELEGATION where not needed; prefer RBCD",
            )
            .with_mitre("T1550.003");
            result.findings.push(finding);
        }
    }

    // RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
    let filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )
        .await.and_then(|r| r.success())
    {
        let hosts: Vec<String> = rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                se.attrs.get("sAMAccountName").and_then(|n| n.first().cloned())
            })
            .collect();

        if !hosts.is_empty() {
            ui::info(&format!("{} host(s) with RBCD configured", hosts.len()));
            for h in &hosts {
                ui::kv("  RBCD", h);
            }
        }
    }
}

async fn collect_maq(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Base,
            "(objectClass=*)",
            vec!["ms-DS-MachineAccountQuota"],
        )
        .await.and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            if let Some(vals) = se.attrs.get("ms-DS-MachineAccountQuota") {
                if let Some(quota) = vals.first() {
                    let q: i32 = quota.parse().unwrap_or(0);
                    ui::kv("Machine Account Quota", quota);
                    if q > 0 {
                        let finding = Finding::new(
                            "ldap",
                            "MAQ-001",
                            Severity::Medium,
                            &format!("Machine Account Quota is {} (default 10)", q),
                        )
                        .with_description("Non-zero MAQ allows any domain user to create machine accounts, enabling RBCD and relay attacks")
                        .with_recommendation("Set ms-DS-MachineAccountQuota to 0")
                        .with_mitre("T1136.002");
                        result.findings.push(finding);
                    }
                }
            }
        }
    }
}

async fn collect_trusts(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(objectClass=trustedDomain)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["cn", "trustDirection", "trustType", "trustAttributes"],
        )
        .await.and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let direction = se
                .attrs
                .get("trustDirection")
                .and_then(|v| v.first())
                .map(|d| match d.as_str() {
                    "1" => "Inbound",
                    "2" => "Outbound",
                    "3" => "Bidirectional",
                    _ => "Unknown",
                })
                .unwrap_or("Unknown");

            ui::kv(&format!("Trust: {}", name), direction);

            let finding = Finding::new(
                "ldap",
                "TRUST-001",
                Severity::Info,
                &format!("Domain trust: {} ({})", name, direction),
            )
            .with_mitre("T1482");
            result.findings.push(finding);
        }
    }
}

async fn collect_adcs_templates(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let config_nc = base.find("DC=").map(|_| {
        let parts: Vec<&str> = base.split(',').collect();
        let dc_parts: Vec<&str> = parts
            .iter()
            .filter(|p| p.starts_with("DC="))
            .copied()
            .collect();
        format!("CN=Configuration,{}", dc_parts.join(","))
    });

    let Some(config_base) = config_nc else { return };
    let templates_base = format!(
        "CN=Certificate Templates,CN=Public Key Services,CN=Services,{}",
        config_base
    );

    // Well-known EKU OIDs
    const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
    const PKINIT: &str = "1.3.6.1.5.2.3.4";
    const SMART_CARD: &str = "1.3.6.1.4.1.311.20.2.2";
    const ANY_PURPOSE: &str = "2.5.29.37.0";
    const CERT_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";
    // SubAltName flag
    const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;

    let filter = "(objectClass=pKICertificateTemplate)";
    if let Ok((rs, _)) = ldap
        .search(
            &templates_base,
            Scope::Subtree,
            filter,
            vec![
                "cn",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "pKIExtendedKeyUsage",
                "msPKI-RA-Signature",
                "nTSecurityDescriptor",
                "msPKI-Template-Schema-Version",
            ],
        )
        .await
        .and_then(|r| r.success())
    {
        let mut esc1 = Vec::new();
        let mut esc2 = Vec::new();
        let mut esc3 = Vec::new();
        let mut esc4 = Vec::new();
        let mut template_count = 0u32;

        for entry in rs {
            let se = SearchEntry::construct(entry);
            template_count += 1;
            let name = se
                .attrs
                .get("cn")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let name_flag: u32 = se
                .attrs
                .get("msPKI-Certificate-Name-Flag")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let ra_sig: u32 = se
                .attrs
                .get("msPKI-RA-Signature")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let eku = se
                .attrs
                .get("pKIExtendedKeyUsage")
                .cloned()
                .unwrap_or_default();

            let supplies_subject = name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT != 0;
            let no_approval = ra_sig == 0;
            let has_client_auth = eku.iter().any(|e| {
                e == CLIENT_AUTH || e == PKINIT || e == SMART_CARD
            });
            let has_any_purpose = eku.iter().any(|e| e == ANY_PURPOSE) || eku.is_empty();
            let has_enrollment_agent = eku.iter().any(|e| e == CERT_REQUEST_AGENT);

            // ESC1: enrollee supplies subject + client auth EKU + no manager approval
            if supplies_subject && has_client_auth && no_approval {
                esc1.push(name.clone());
                ui::warning(&format!("  ESC1: {} — enrollee supplies subject + client auth", name));
            }

            // ESC2: any-purpose EKU or no EKU (SubCA) + no manager approval
            if has_any_purpose && no_approval && !has_client_auth {
                esc2.push(name.clone());
                ui::warning(&format!("  ESC2: {} — any purpose / no EKU restrictions", name));
            }

            // ESC3: enrollment agent EKU + no approval
            if has_enrollment_agent && no_approval {
                esc3.push(name.clone());
                ui::warning(&format!("  ESC3: {} — certificate request agent EKU", name));
            }

            // ESC4: check if we can read nTSecurityDescriptor (indicates we might have write access)
            // Full ACL parsing requires binary SD parsing; flag templates where SD is readable as potential ESC4
            if se.bin_attrs.contains_key("nTSecurityDescriptor") {
                // We can read the SD — note it for manual review
                esc4.push(name.clone());
            }
        }

        ui::info(&format!("{} certificate template(s) enumerated", template_count));

        if !esc1.is_empty() {
            let finding = Finding::new(
                "ldap",
                "ADCS-ESC1",
                Severity::Critical,
                &format!("{} template(s) vulnerable to ESC1", esc1.len()),
            )
            .with_description(
                "Templates allow enrollee to supply the subject name with Client Authentication EKU and no manager approval — enables domain privilege escalation via certificate impersonation",
            )
            .with_evidence(&esc1.join(", "))
            .with_recommendation(
                "Remove ENROLLEE_SUPPLIES_SUBJECT flag, restrict enrollment permissions, or require manager approval",
            )
            .with_mitre("T1649");
            result.findings.push(finding);
        }

        if !esc2.is_empty() {
            let finding = Finding::new(
                "ldap",
                "ADCS-ESC2",
                Severity::High,
                &format!("{} template(s) vulnerable to ESC2", esc2.len()),
            )
            .with_description(
                "Templates have Any Purpose EKU or no EKU restrictions — can be used as subordinate CA or for any authentication purpose",
            )
            .with_evidence(&esc2.join(", "))
            .with_recommendation(
                "Restrict EKU to specific purposes; remove Any Purpose OID",
            )
            .with_mitre("T1649");
            result.findings.push(finding);
        }

        if !esc3.is_empty() {
            let finding = Finding::new(
                "ldap",
                "ADCS-ESC3",
                Severity::High,
                &format!("{} template(s) vulnerable to ESC3", esc3.len()),
            )
            .with_description(
                "Templates have Certificate Request Agent EKU — allows enrolling on behalf of other users including admins",
            )
            .with_evidence(&esc3.join(", "))
            .with_recommendation(
                "Restrict enrollment agent templates to dedicated RA accounts; enable enrollment agent restrictions on the CA",
            )
            .with_mitre("T1649");
            result.findings.push(finding);
        }

        if !esc4.is_empty() {
            ui::verbose(&format!(
                "ESC4 candidates (SD readable, review ACLs): {}",
                esc4.join(", ")
            ));
        }
    }

    // ESC6: Check CA object for EDITF_ATTRIBUTESUBJECTALTNAME2
    let ca_base = format!(
        "CN=Enrollment Services,CN=Public Key Services,CN=Services,{}",
        config_base
    );
    if let Ok((rs, _)) = ldap
        .search(
            &ca_base,
            Scope::Subtree,
            "(objectClass=pKIEnrollmentService)",
            vec!["cn", "flags", "cACertificate", "certificateTemplates"],
        )
        .await
        .and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let ca_name = se
                .attrs
                .get("cn")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let flags: u32 = se
                .attrs
                .get("flags")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            // EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
            if flags & 0x00040000 != 0 {
                ui::warning(&format!(
                    "  ESC6: CA '{}' has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
                    ca_name
                ));
                let finding = Finding::new(
                    "ldap",
                    "ADCS-ESC6",
                    Severity::Critical,
                    &format!(
                        "CA '{}' has EDITF_ATTRIBUTESUBJECTALTNAME2 — any template can specify SAN",
                        ca_name
                    ),
                )
                .with_description(
                    "The CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, allowing ANY certificate request to specify an arbitrary Subject Alternative Name. This means even templates without ENROLLEE_SUPPLIES_SUBJECT can be abused for impersonation.",
                )
                .with_recommendation(
                    "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA: certutil -config 'CA' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
                )
                .with_mitre("T1649");
                result.findings.push(finding);
            }

            // Show enrolled templates
            if let Some(templates) = se.attrs.get("certificateTemplates") {
                ui::verbose(&format!(
                    "CA '{}' enrolls: {}",
                    ca_name,
                    templates.join(", ")
                ));
            }
        }
    }
}

async fn collect_computers(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(objectCategory=computer)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "operatingSystem", "operatingSystemVersion"],
        )
        .await.and_then(|r| r.success())
    {
        let mut obsolete = Vec::new();
        let mut os_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let obsolete_patterns = [
            "Windows Server 2003",
            "Windows Server 2008",
            "Windows XP",
            "Windows 7",
            "Windows Vista",
            "Windows Server 2012",
        ];

        for entry in rs {
            let se = SearchEntry::construct(entry);
            let os = se.attrs.get("operatingSystem").and_then(|v| v.first()).cloned().unwrap_or_default();
            let name = se.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();

            if !name.is_empty() {
                result.collected_users.push(name.clone());
            }

            if !os.is_empty() {
                *os_counts.entry(os.clone()).or_insert(0) += 1;
            }

            if obsolete_patterns.iter().any(|p| os.contains(p)) {
                obsolete.push(format!("{} ({})", name, os));
            }
        }

        // Show OS inventory
        let total: u32 = os_counts.values().sum();
        ui::info(&format!("{} computer objects found", total));
        let mut sorted_os: Vec<_> = os_counts.into_iter().collect();
        sorted_os.sort_by(|a, b| b.1.cmp(&a.1));
        for (os, count) in sorted_os.iter().take(10) {
            ui::kv(&format!("  {} ({}x)", os, count), "");
        }

        if !obsolete.is_empty() {
            let finding = Finding::new(
                "ldap",
                "COMP-001",
                Severity::Medium,
                &format!("{} obsolete OS computer(s) found", obsolete.len()),
            )
            .with_description("End-of-life operating systems lack security patches and are high-value targets")
            .with_evidence(&obsolete.join("\n"))
            .with_recommendation("Decommission or isolate obsolete systems");
            result.findings.push(finding);
        }
    }
}

async fn collect_password_policy(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    // Fine-grained password policies
    let filter = "(objectClass=msDS-PasswordSettings)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec![
                "cn",
                "msDS-MinimumPasswordLength",
                "msDS-LockoutThreshold",
                "msDS-PasswordComplexityEnabled",
            ],
        )
        .await.and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let min_len: u32 = se
                .attrs
                .get("msDS-MinimumPasswordLength")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            ui::kv(&format!("PSO: {}", name), &format!("minLength={}", min_len));

            if min_len < 12 {
                let finding = Finding::new(
                    "ldap",
                    "PSO-001",
                    Severity::Low,
                    &format!("Weak password policy: {} (minLength={})", name, min_len),
                )
                .with_recommendation("Set minimum password length to at least 14 characters");
                result.findings.push(finding);
            }
        }
    }
}

async fn collect_dcsync_heuristics(ldap: &mut ldap3::Ldap, base: &str, _result: &mut ModuleResult) {
    // Check for non-default accounts with replication rights
    let filter = "(&(objectClass=group)(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Administrators)))";
    if let Ok((rs, _)) = ldap
        .search(base, Scope::Subtree, filter, vec!["cn", "member"])
        .await.and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let members = se.attrs.get("member").cloned().unwrap_or_default();
            ui::kv(&format!("  {}", name), &format!("{} member(s)", members.len()));
        }
    }
}

async fn collect_laps(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    // Check LAPS v1 (legacy) attributes
    let v1_filter = "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))";
    let mut v1_readable = Vec::new();
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            v1_filter,
            vec!["sAMAccountName", "ms-Mcs-AdmPwd"],
        )
        .await
        .and_then(|r| r.success())
    {
        for e in rs {
            let se = SearchEntry::construct(e);
            if se.attrs.contains_key("ms-Mcs-AdmPwd") {
                if let Some(name) = se.attrs.get("sAMAccountName").and_then(|v| v.first()) {
                    v1_readable.push(name.clone());
                }
            }
        }
    }

    if !v1_readable.is_empty() {
        ui::warning(&format!(
            "LAPS v1 passwords readable for {} host(s)",
            v1_readable.len()
        ));
        let finding = Finding::new(
            "ldap",
            "LAPS-001",
            Severity::High,
            &format!(
                "LAPS v1 passwords readable for {} computer(s)",
                v1_readable.len()
            ),
        )
        .with_description(
            "Current credentials can read legacy LAPS (ms-Mcs-AdmPwd) local admin passwords",
        )
        .with_evidence(&v1_readable.join(", "))
        .with_recommendation("Restrict LAPS read permissions; migrate to Windows LAPS (v2)")
        .with_mitre("T1555");
        result.findings.push(finding);
    }

    // Check LAPS v2 (Windows LAPS) attributes
    let v2_filter =
        "(&(objectCategory=computer)(|(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))";
    let mut v2_readable = Vec::new();
    let mut v2_encrypted = Vec::new();
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            v2_filter,
            vec![
                "sAMAccountName",
                "msLAPS-Password",
                "msLAPS-EncryptedPassword",
            ],
        )
        .await
        .and_then(|r| r.success())
    {
        for e in rs {
            let se = SearchEntry::construct(e);
            let name = se
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            if se.attrs.contains_key("msLAPS-Password") {
                v2_readable.push(name.clone());
            }
            if se.attrs.contains_key("msLAPS-EncryptedPassword") {
                v2_encrypted.push(name);
            }
        }
    }

    if !v2_readable.is_empty() {
        ui::warning(&format!(
            "LAPS v2 cleartext passwords readable for {} host(s)",
            v2_readable.len()
        ));
        let finding = Finding::new(
            "ldap",
            "LAPS-002",
            Severity::High,
            &format!(
                "Windows LAPS v2 passwords readable for {} computer(s)",
                v2_readable.len()
            ),
        )
        .with_description(
            "Current credentials can read Windows LAPS (msLAPS-Password) local admin passwords in cleartext",
        )
        .with_evidence(&v2_readable.join(", "))
        .with_recommendation(
            "Restrict LAPS read permissions; enable LAPS password encryption",
        )
        .with_mitre("T1555");
        result.findings.push(finding);
    }

    if !v2_encrypted.is_empty() {
        ui::info(&format!(
            "LAPS v2 encrypted passwords visible for {} host(s) (encrypted — requires DSRM key to decrypt)",
            v2_encrypted.len()
        ));
    }

    // Summary
    let total = v1_readable.len() + v2_readable.len();
    if total == 0 {
        // Check if LAPS is deployed at all
        let any_laps = "(&(objectCategory=computer)(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*)))";
        if let Ok((rs, _)) = ldap
            .search(base, Scope::Subtree, any_laps, vec!["sAMAccountName"])
            .await
            .and_then(|r| r.success())
        {
            if rs.is_empty() {
                ui::info("LAPS does not appear to be deployed in this domain");
            } else {
                ui::success(&format!(
                    "LAPS deployed on {} host(s) — passwords not readable with current creds",
                    rs.len()
                ));
            }
        }
    }
}

async fn collect_gpos(ldap: &mut ldap3::Ldap, base: &str, _result: &mut ModuleResult) {
    let filter = "(objectClass=groupPolicyContainer)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["displayName", "gPCFileSysPath", "flags"],
        )
        .await.and_then(|r| r.success())
    {
        let count = rs.len();
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se
                .attrs
                .get("displayName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let path = se
                .attrs
                .get("gPCFileSysPath")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            if !name.is_empty() {
                ui::kv(&format!("  GPO: {}", name), &path);
            }
        }
        ui::info(&format!("{} GPO(s) enumerated", count));
    }
}

async fn collect_shadow_credentials(
    ldap: &mut ldap3::Ldap,
    base: &str,
    result: &mut ModuleResult,
) {
    // Check for objects with msDS-KeyCredentialLink (shadow credentials)
    let filter = "(msDS-KeyCredentialLink=*)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "objectClass"],
        )
        .await.and_then(|r| r.success())
    {
        let objects: Vec<String> = rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                se.attrs.get("sAMAccountName").and_then(|v| v.first().cloned())
            })
            .collect();

        if !objects.is_empty() {
            ui::info(&format!(
                "{} object(s) with shadow credentials (msDS-KeyCredentialLink)",
                objects.len()
            ));
            for obj in &objects {
                ui::kv("  Shadow Cred", obj);
            }
            let finding = Finding::new(
                "ldap",
                "SHADOW-001",
                Severity::Info,
                &format!("{} object(s) with shadow credentials configured", objects.len()),
            )
            .with_description("msDS-KeyCredentialLink is set, which could indicate WHfB or Shadow Credentials attack")
            .with_mitre("T1556.007");
            result.findings.push(finding);
        }
    }
}

async fn collect_user_descriptions(
    ldap: &mut ldap3::Ldap,
    base: &str,
    result: &mut ModuleResult,
) {
    let filter = "(&(objectClass=user)(objectCategory=person)(description=*))";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "description"],
        )
        .await.and_then(|r| r.success())
    {
        let password_hints = [
            "pass", "pwd", "password", "cred", "secret", "p@ss", "key", "login",
        ];
        let mut suspicious = Vec::new();

        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
            let desc = se.attrs.get("description").and_then(|v| v.first()).cloned().unwrap_or_default();

            if password_hints
                .iter()
                .any(|h| desc.to_ascii_lowercase().contains(h))
            {
                suspicious.push(format!("{}: {}", name, desc));
            }
        }

        if !suspicious.is_empty() {
            ui::warning(&format!("{} user(s) with password hints in description", suspicious.len()));
            for s in &suspicious {
                ui::kv("  Hint", s);
            }
            let finding = Finding::new(
                "ldap",
                "USER-001",
                Severity::High,
                &format!("{} user description(s) contain password hints", suspicious.len()),
            )
            .with_description("User descriptions contain keywords suggesting passwords are stored in cleartext")
            .with_evidence(&suspicious.join("\n"))
            .with_recommendation("Remove passwords from description fields; use a vault or PAM solution")
            .with_mitre("T1552.001");
            result.findings.push(finding);
        }
    }
}

// ── Domain password policy ──────────────────────────────────────────────────

async fn collect_domain_password_policy(
    ldap: &mut ldap3::Ldap,
    base: &str,
) -> Option<DomainPasswordPolicy> {
    // Query the domain root for default password policy attributes
    let attrs = vec![
        "minPwdLength",
        "lockoutThreshold",
        "lockOutObservationWindow",
        "lockoutDuration",
        "maxPwdAge",
        "pwdHistoryLength",
        "pwdProperties",
    ];
    let Ok((rs, _)) = ldap
        .search(base, Scope::Base, "(objectClass=*)", attrs)
        .await
        .and_then(|r| r.success())
    else {
        return None;
    };

    let entry = rs.into_iter().next()?;
    let se = SearchEntry::construct(entry);

    let get_u32 = |key: &str| -> u32 {
        se.attrs
            .get(key)
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };

    // AD stores time intervals as negative 100-nanosecond intervals
    let nt_interval_to_minutes = |key: &str| -> u64 {
        let raw: i64 = se
            .attrs
            .get(key)
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if raw == 0 || raw == i64::MIN {
            return 0;
        }
        let positive = raw.unsigned_abs();
        positive / 600_000_000 // 100ns ticks -> minutes
    };

    let nt_interval_to_days = |key: &str| -> u64 {
        let raw: i64 = se
            .attrs
            .get(key)
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if raw == 0 || raw == i64::MIN {
            return 0;
        }
        let positive = raw.unsigned_abs();
        positive / 864_000_000_000 // 100ns ticks -> days
    };

    let pwd_properties = get_u32("pwdProperties");

    Some(DomainPasswordPolicy {
        min_pwd_length: get_u32("minPwdLength"),
        lockout_threshold: get_u32("lockoutThreshold"),
        lockout_observation_window_min: nt_interval_to_minutes("lockOutObservationWindow"),
        lockout_duration_min: nt_interval_to_minutes("lockoutDuration"),
        max_pwd_age_days: nt_interval_to_days("maxPwdAge"),
        pwd_history_length: get_u32("pwdHistoryLength"),
        complexity_enabled: pwd_properties & 1 != 0,
    })
}

// ── gMSA readability ───────────────────────────────────────────────────────

async fn collect_gmsa(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(objectClass=msDS-GroupManagedServiceAccount)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "msDS-GroupMSAMembership",
                "msDS-ManagedPasswordId",
            ],
        )
        .await
        .and_then(|r| r.success())
    {
        let mut gmsa_accounts = Vec::new();
        let mut readable = Vec::new();

        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            gmsa_accounts.push(name.clone());

            // If we can read the msDS-ManagedPasswordId, we likely have read access
            if se.attrs.contains_key("msDS-ManagedPasswordId") {
                readable.push(name);
            }
        }

        if !gmsa_accounts.is_empty() {
            ui::info(&format!("{} gMSA account(s) found", gmsa_accounts.len()));
            for a in &gmsa_accounts {
                ui::kv("  gMSA", a);
            }
        }

        if !readable.is_empty() {
            ui::warning(&format!(
                "gMSA password potentially readable for {} account(s)",
                readable.len()
            ));
            let finding = Finding::new(
                "ldap",
                "GMSA-001",
                Severity::High,
                &format!(
                    "gMSA password readable for {} account(s)",
                    readable.len()
                ),
            )
            .with_description(
                "Current credentials can read gMSA managed password attributes, enabling password extraction",
            )
            .with_evidence(&readable.join(", "))
            .with_recommendation(
                "Restrict msDS-GroupMSAMembership to only the accounts that need to retrieve the password",
            )
            .with_mitre("T1555");
            result.findings.push(finding);
        }
    }
}

// ── Deleted but recoverable objects ─────────────────────────────────────────

async fn collect_deleted_objects(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    // LDAP_SERVER_SHOW_DELETED_OID — required to see objects in CN=Deleted Objects
    let show_deleted = RawControl {
        ctype: "1.2.840.113556.1.4.417".to_string(),
        crit: true,
        val: None,
    };

    let deleted_base = format!("CN=Deleted Objects,{}", base);
    let filter =
        "(&(isDeleted=TRUE)(!(isRecycled=TRUE))(|(objectClass=user)(objectClass=computer)))";

    let search_result = ldap
        .with_controls(vec![show_deleted])
        .search(
            &deleted_base,
            Scope::OneLevel,
            filter,
            vec!["cn", "sAMAccountName", "whenChanged", "objectClass"],
        )
        .await
        .and_then(|r| r.success());

    match search_result {
        Ok((rs, _)) => {
            let mut deleted = Vec::new();
            for entry in rs {
                let se = SearchEntry::construct(entry);
                let name = se
                    .attrs
                    .get("sAMAccountName")
                    .or(se.attrs.get("cn"))
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                let when = se
                    .attrs
                    .get("whenChanged")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                if !name.is_empty() {
                    if when.is_empty() {
                        deleted.push(name);
                    } else {
                        deleted.push(format!("{} (deleted: {})", name, when));
                    }
                }
            }

            if !deleted.is_empty() {
                ui::warning(&format!(
                    "{} deleted but recoverable object(s) in Recycle Bin",
                    deleted.len()
                ));
                for d in deleted.iter().take(20) {
                    ui::kv("  Recoverable", d);
                }
                if deleted.len() > 20 {
                    ui::info(&format!("  ... and {} more", deleted.len() - 20));
                }
                let finding = Finding::new(
                    "ldap",
                    "DEL-001",
                    Severity::Low,
                    &format!(
                        "{} deleted AD object(s) recoverable via Recycle Bin",
                        deleted.len()
                    ),
                )
                .with_description(
                    "Deleted user/computer accounts in the AD Recycle Bin can be restored with original permissions and group memberships",
                )
                .with_evidence(
                    &deleted
                        .iter()
                        .take(50)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
                .with_recommendation(
                    "Review and permanently purge deleted accounts; ensure Recycle Bin retention aligns with policy",
                );
                result.findings.push(finding);
            } else {
                ui::info("No recoverable deleted objects found");
            }
        }
        Err(e) => {
            ui::verbose(&format!(
                "Deleted objects query failed: {} (Recycle Bin may not be enabled)",
                e
            ));
            ui::info("AD Recycle Bin check: could not query (may not be enabled)");
        }
    }
}

// ── Pre-Windows 2000 Compatible Access ─────────────────────────────────────

async fn collect_pre2000_group(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let group_dn = format!(
        "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{}",
        base
    );
    if let Ok((rs, _)) = ldap
        .search(&group_dn, Scope::Base, "(objectClass=*)", vec!["member"])
        .await
        .and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let members = se.attrs.get("member").cloned().unwrap_or_default();

            // Well-known SIDs stored as ForeignSecurityPrincipal DNs
            let has_auth_users = members.iter().any(|m| m.contains("S-1-5-11"));
            let has_everyone = members.iter().any(|m| m.contains("S-1-1-0"));
            let has_anonymous = members.iter().any(|m| m.contains("S-1-5-7"));

            if has_auth_users || has_everyone || has_anonymous {
                let mut dangerous = Vec::new();
                if has_auth_users {
                    dangerous.push("Authenticated Users (S-1-5-11)");
                }
                if has_everyone {
                    dangerous.push("Everyone (S-1-1-0)");
                }
                if has_anonymous {
                    dangerous.push("Anonymous Logon (S-1-5-7)");
                }

                ui::warning(&format!(
                    "Pre-Windows 2000 group contains: {}",
                    dangerous.join(", ")
                ));
                let finding = Finding::new(
                    "ldap",
                    "PRE2K-001",
                    Severity::Medium,
                    "Pre-Windows 2000 Compatible Access includes broad identity groups",
                )
                .with_description(
                    "This group grants read access to AD user/group attributes. Including 'Authenticated Users' or 'Everyone' allows any domain user to enumerate all objects.",
                )
                .with_evidence(&dangerous.join(", "))
                .with_recommendation(
                    "Remove 'Authenticated Users' and 'Everyone' from this group",
                )
                .with_mitre("T1087.002");
                result.findings.push(finding);
            } else {
                ui::info(&format!(
                    "Pre-Windows 2000 group: {} member(s) (no broad identity groups)",
                    members.len()
                ));
            }
        }
    }
}

// ── Inactive / stale accounts ──────────────────────────────────────────────

async fn collect_inactive_accounts(
    ldap: &mut ldap3::Ldap,
    base: &str,
    result: &mut ModuleResult,
) {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ninety_days = 90u64 * 86400;
    let threshold_unix = now_unix.saturating_sub(ninety_days);
    let filetime_epoch_diff = 11_644_473_600u64;
    let threshold_ft = (threshold_unix + filetime_epoch_diff) * 10_000_000;

    let filter = format!(
        "(&(objectClass=user)(objectCategory=person)(lastLogonTimestamp<={})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        threshold_ft
    );

    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            &filter,
            vec!["sAMAccountName", "lastLogonTimestamp"],
        )
        .await
        .and_then(|r| r.success())
    {
        let mut stale = Vec::new();
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let last_logon: u64 = se
                .attrs
                .get("lastLogonTimestamp")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            if !name.is_empty() && last_logon > 0 {
                let logon_unix = (last_logon / 10_000_000).saturating_sub(filetime_epoch_diff);
                let days_ago = now_unix.saturating_sub(logon_unix) / 86400;
                stale.push(format!("{} ({}d)", name, days_ago));
            }
        }

        if !stale.is_empty() {
            ui::warning(&format!(
                "{} inactive account(s) (>90 days since last logon)",
                stale.len()
            ));
            for s in stale.iter().take(15) {
                ui::kv("  Stale", s);
            }
            if stale.len() > 15 {
                ui::info(&format!("  ... and {} more", stale.len() - 15));
            }
            let finding = Finding::new(
                "ldap",
                "ACCT-001",
                Severity::Medium,
                &format!(
                    "{} inactive account(s) with no logon in 90+ days",
                    stale.len()
                ),
            )
            .with_description(
                "Accounts with no recent logon activity are prime targets for credential attacks and may indicate abandoned accounts",
            )
            .with_evidence(
                &stale
                    .iter()
                    .take(50)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .with_recommendation(
                "Disable inactive accounts; implement automated account lifecycle management",
            )
            .with_mitre("T1078.002");
            result.findings.push(finding);
        }
    }
}

// ── Privileged group recursive membership ──────────────────────────────────

async fn collect_privileged_groups(
    ldap: &mut ldap3::Ldap,
    base: &str,
    result: &mut ModuleResult,
) {
    let groups = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "DnsAdmins",
    ];

    let mut all_privileged: Vec<String> = Vec::new();
    let mut group_details = Vec::new();

    for group_name in &groups {
        // Find the group DN
        let gfilter = format!("(&(objectClass=group)(cn={}))", group_name);
        let dn = match ldap
            .search(base, Scope::Subtree, &gfilter, vec!["distinguishedName"])
            .await
            .and_then(|r| r.success())
        {
            Ok((rs, _)) => rs.into_iter().next().map(|e| {
                let se = SearchEntry::construct(e);
                se.dn
            }),
            Err(_) => None,
        };

        let Some(group_dn) = dn else { continue };

        // Recursive membership via LDAP_MATCHING_RULE_IN_CHAIN
        let mfilter = format!(
            "(&(objectClass=user)(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:={}))",
            group_dn
        );

        if let Ok((rs, _)) = ldap
            .search(base, Scope::Subtree, &mfilter, vec!["sAMAccountName"])
            .await
            .and_then(|r| r.success())
        {
            let members: Vec<String> = rs
                .into_iter()
                .filter_map(|e| {
                    let se = SearchEntry::construct(e);
                    se.attrs
                        .get("sAMAccountName")
                        .and_then(|v| v.first().cloned())
                })
                .collect();

            if !members.is_empty() {
                let display = if members.len() <= 5 {
                    members.join(", ")
                } else {
                    format!(
                        "{}, ... +{} more",
                        members[..5].join(", "),
                        members.len() - 5
                    )
                };
                ui::kv(
                    &format!("  {} (recursive)", group_name),
                    &format!("{}: {}", members.len(), display),
                );
                group_details.push(format!("{}: {} member(s)", group_name, members.len()));
                all_privileged.extend(members);
            }
        }
    }

    // Deduplicate
    all_privileged.sort_by_key(|u| u.to_lowercase());
    all_privileged.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

    if !all_privileged.is_empty() {
        ui::info(&format!(
            "{} unique privileged user(s) across {} group(s)",
            all_privileged.len(),
            group_details.len()
        ));

        if all_privileged.len() > 15 {
            let finding = Finding::new(
                "ldap",
                "PRIV-001",
                Severity::Medium,
                &format!(
                    "{} privileged accounts — excessive admin footprint",
                    all_privileged.len()
                ),
            )
            .with_description(
                "Large number of accounts in privileged groups increases the attack surface for credential theft and lateral movement",
            )
            .with_evidence(&group_details.join("\n"))
            .with_recommendation(
                "Apply least-privilege: remove unnecessary members; use tiered administration",
            )
            .with_mitre("T1078.002");
            result.findings.push(finding);
        }
    }
}

// ── AdminSDHolder ──────────────────────────────────────────────────────────

async fn collect_adminsdholder(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(&(objectClass=user)(adminCount=1)(!(|(sAMAccountName=Administrator)(sAMAccountName=krbtgt))))";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "memberOf"],
        )
        .await
        .and_then(|r| r.success())
    {
        let accounts: Vec<String> = rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                se.attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first().cloned())
            })
            .collect();

        if !accounts.is_empty() {
            ui::info(&format!(
                "{} account(s) with adminCount=1 (AdminSDHolder protected)",
                accounts.len()
            ));
            for a in accounts.iter().take(20) {
                ui::kv("  AdminSDHolder", a);
            }
            if accounts.len() > 20 {
                ui::info(&format!("  ... and {} more", accounts.len() - 20));
            }

            let finding = Finding::new(
                "ldap",
                "ADMIN-001",
                Severity::Info,
                &format!(
                    "{} non-default account(s) with adminCount=1",
                    accounts.len()
                ),
            )
            .with_description(
                "Accounts with adminCount=1 are protected by AdminSDHolder (ACLs reset every 60 min). Some may be orphaned — removed from privileged groups but still flagged.",
            )
            .with_evidence(
                &accounts
                    .iter()
                    .take(50)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .with_recommendation(
                "Audit adminCount=1 accounts; clear adminCount on accounts no longer in privileged groups",
            );
            result.findings.push(finding);
        }
    }
}

// ── SID History ────────────────────────────────────────────────────────────

async fn collect_sid_history(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(&(objectClass=user)(sIDHistory=*))";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "sIDHistory"],
        )
        .await
        .and_then(|r| r.success())
    {
        let mut users_with_sid_history = Vec::new();
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            // sIDHistory is binary — count entries
            let count = se
                .bin_attrs
                .get("sIDHistory")
                .map(|v| v.len())
                .unwrap_or(0);
            if !name.is_empty() {
                users_with_sid_history.push(format!("{} ({} SID(s))", name, count));
            }
        }

        if !users_with_sid_history.is_empty() {
            ui::warning(&format!(
                "{} account(s) with SID History",
                users_with_sid_history.len()
            ));
            for u in &users_with_sid_history {
                ui::kv("  SID History", u);
            }
            let finding = Finding::new(
                "ldap",
                "SID-001",
                Severity::High,
                &format!(
                    "{} account(s) with SID History set",
                    users_with_sid_history.len()
                ),
            )
            .with_description(
                "SID History allows an account to inherit access of another SID. Attackers use this for privilege escalation by injecting high-privilege SIDs.",
            )
            .with_evidence(&users_with_sid_history.join("\n"))
            .with_recommendation(
                "Audit SID History entries; remove after migration is complete; monitor for SID History injection",
            )
            .with_mitre("T1134.005");
            result.findings.push(finding);
        }
    }
}

// ── Service account heuristics ─────────────────────────────────────────────

async fn collect_service_accounts(
    ldap: &mut ldap3::Ldap,
    base: &str,
    result: &mut ModuleResult,
) {
    let filter = "(&(objectClass=user)(objectCategory=person)(|(sAMAccountName=*svc*)(sAMAccountName=*service*)(sAMAccountName=*sql*)(sAMAccountName=*backup*)(sAMAccountName=*scan*)(sAMAccountName=*batch*)(sAMAccountName=*task*)(sAMAccountName=*iis*)(sAMAccountName=svc_*)(sAMAccountName=sa_*)))";

    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "userAccountControl",
                "servicePrincipalName",
                "adminCount",
            ],
        )
        .await
        .and_then(|r| r.success())
    {
        let mut svc_accounts = Vec::new();
        let mut pwd_never_expires = Vec::new();
        let mut with_admin = Vec::new();

        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let uac: u32 = se
                .attrs
                .get("userAccountControl")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let has_spn = se.attrs.contains_key("servicePrincipalName");
            let admin_count: u32 = se
                .attrs
                .get("adminCount")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            // DONT_EXPIRE_PASSWORD = 0x10000, ACCOUNTDISABLE = 0x2
            let pwd_no_expire = uac & 0x10000 != 0;
            let disabled = uac & 0x2 != 0;
            if disabled {
                continue;
            }

            let mut flags = Vec::new();
            if has_spn {
                flags.push("SPN");
            }
            if pwd_no_expire {
                flags.push("PWD_NEVER_EXPIRES");
            }
            if admin_count > 0 {
                flags.push("ADMIN");
            }

            let entry_str = if flags.is_empty() {
                name.clone()
            } else {
                format!("{} [{}]", name, flags.join(", "))
            };
            svc_accounts.push(entry_str);

            if pwd_no_expire {
                pwd_never_expires.push(name.clone());
            }
            if admin_count > 0 {
                with_admin.push(name.clone());
            }
        }

        if !svc_accounts.is_empty() {
            ui::info(&format!(
                "{} service account(s) identified by naming convention",
                svc_accounts.len()
            ));
            for s in svc_accounts.iter().take(20) {
                ui::kv("  Service Acct", s);
            }
            if svc_accounts.len() > 20 {
                ui::info(&format!("  ... and {} more", svc_accounts.len() - 20));
            }
        }

        if !pwd_never_expires.is_empty() {
            let finding = Finding::new(
                "ldap",
                "SVC-001",
                Severity::Medium,
                &format!(
                    "{} service account(s) with password never expires",
                    pwd_never_expires.len()
                ),
            )
            .with_description(
                "Service accounts with DONT_EXPIRE_PASSWORD are high-value targets — stale passwords are more likely to be cracked",
            )
            .with_evidence(&pwd_never_expires.join(", "))
            .with_recommendation(
                "Migrate to gMSA for automatic rotation; or enforce regular password changes",
            )
            .with_mitre("T1078.002");
            result.findings.push(finding);
        }

        if !with_admin.is_empty() {
            let finding = Finding::new(
                "ldap",
                "SVC-002",
                Severity::High,
                &format!(
                    "{} service account(s) with admin privileges",
                    with_admin.len()
                ),
            )
            .with_description(
                "Service accounts with adminCount=1 have administrative privileges. Compromising these provides broad domain access.",
            )
            .with_evidence(&with_admin.join(", "))
            .with_recommendation(
                "Apply least-privilege: remove admin rights from service accounts; use separate admin and service tiers",
            )
            .with_mitre("T1078.002");
            result.findings.push(finding);
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn functional_level_label(level: &str) -> &str {
    match level {
        "0" => "2000",
        "1" => "2003 Interim",
        "2" => "2003",
        "3" => "2008",
        "4" => "2008 R2",
        "5" => "2012",
        "6" => "2012 R2",
        "7" => "2016",
        "8" => "2019 (Preview)",
        "9" => "2022",
        "10" => "2025",
        _ => level,
    }
}

fn check_ldap_signing(_result: &mut ModuleResult) {
    // LDAP signing check is typically done via NTLM negotiation
    // For now we note it as info
    ui::info("LDAP signing check: requires NTLM negotiation (check via SMB/RPC)");
}
