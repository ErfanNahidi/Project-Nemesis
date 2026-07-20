use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::types::{Finding, ModuleResult, Severity, StageTimer};
use crate::ui;

/// Run unauthenticated attack surface checks.
/// Covers: AD CS Web Enrollment, coercion endpoints, NTLM relay surface.
pub async fn run(target: &str, open_ports: &[u16]) -> Result<ModuleResult> {
    ui::section("ATTACK SURFACE ANALYSIS");
    let timer = StageTimer::start();
    let spin = ui::spinner("ATTACKS");
    let mut result = ModuleResult::new("attacks");

    // AD CS Web Enrollment
    let web_ports: Vec<u16> = open_ports
        .iter()
        .copied()
        .filter(|p| matches!(p, 80 | 8080))
        .collect();
    let tls_ports: Vec<u16> = open_ports
        .iter()
        .copied()
        .filter(|p| matches!(p, 443 | 8443))
        .collect();

    if !web_ports.is_empty() || !tls_ports.is_empty() {
        spin.set_message("checking AD CS Web Enrollment...");
        for port in &web_ports {
            check_adcs_enrollment(target, "http", *port, &mut result).await;
        }
        for port in &tls_ports {
            check_adcs_enrollment(target, "https", *port, &mut result).await;
        }
    }

    // SMB signing check
    if open_ports.contains(&445) {
        spin.set_message("checking SMB signing...");
        check_smb_signing(target, &mut result).await;
    }

    // Coercion attack surface
    if open_ports.contains(&445) {
        spin.set_message("checking coercion attack surface...");
        check_coercion_surface(target, open_ports, &mut result).await;
    }

    // WebDAV check (for relay)
    if open_ports.contains(&80) || open_ports.contains(&8080) {
        spin.set_message("checking WebDAV...");
        check_webdav(target, &web_ports, &mut result).await;
    }

    let finding_count = result.findings.len();
    ui::finish_spinner(&spin, &format!("{} attack surface findings", finding_count));
    ui::stage_done("ATTACKS", &format!("{} findings", finding_count), &timer.elapsed_pretty());

    result = result.success(timer.elapsed());
    Ok(result)
}

// ── AD CS Web Enrollment ────────────────────────────────────────────────────

async fn check_adcs_enrollment(
    target: &str,
    scheme: &str,
    port: u16,
    result: &mut ModuleResult,
) {
    let paths = ["/certsrv/", "/certsrv/certfnsh.asp", "/certsrv/certnew.cer"];
    let mut seen_adcs = false;
    let mut ntlm_auth = false;
    let mut anon_ok = false;

    for path in paths {
        let response = if scheme == "https" {
            https_probe(target, port, path).await
        } else {
            http_probe(target, port, path).await
        };

        let Ok(resp) = response else {
            ui::verbose(&format!("ADCS probe failed: {}://{}:{}{}", scheme, target, port, path));
            continue;
        };

        ui::verbose(&format!(
            "ADCS probe {}://{}:{}{} → {} (headers: {})",
            scheme, target, port, path, resp.status,
            resp.headers.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(", ")
        ));

        let offers_ntlm = resp
            .headers
            .iter()
            .any(|(k, v)| {
                k.eq_ignore_ascii_case("www-authenticate")
                    && (v.to_lowercase().contains("ntlm") || v.to_lowercase().contains("negotiate"))
            });

        if path.starts_with("/certsrv/") && (resp.status == 200 || resp.status == 401) {
            seen_adcs = true;
        }
        if resp.status == 401 && offers_ntlm {
            ntlm_auth = true;
        }
        if resp.status == 200 {
            anon_ok = true;
        }
    }

    if seen_adcs {
        ui::warning(&format!(
            "AD CS Web Enrollment detected on {}://{}:{}",
            scheme, target, port
        ));

        if ntlm_auth {
            let finding = Finding::new(
                "attacks",
                "ADCS-ESC8",
                Severity::Critical,
                "AD CS Web Enrollment with NTLM auth (ESC8)",
            )
            .with_description(
                "AD CS Web Enrollment offers NTLM/Negotiate authentication, enabling relay-to-ADCS attacks (ESC8)"
            )
            .with_recommendation("Disable Web Enrollment, enforce EPA, require HTTPS with channel binding")
            .with_mitre("T1557.001");
            result.findings.push(finding);
            ui::warning("NTLM auth on /certsrv — ESC8 relay attack possible!");
        }

        if anon_ok {
            let finding = Finding::new(
                "attacks",
                "ADCS-ANON",
                Severity::High,
                "AD CS Web Enrollment accessible without authentication",
            )
            .with_description("Anonymous access to AD CS Web Enrollment endpoints")
            .with_recommendation("Require authentication for all AD CS endpoints");
            result.findings.push(finding);
            ui::warning("Anonymous access to /certsrv endpoint!");
        }

        if !ntlm_auth && !anon_ok {
            let finding = Finding::new(
                "attacks",
                "ADCS-PRESENT",
                Severity::Info,
                &format!("AD CS Web Enrollment present on {}://{}:{}", scheme, target, port),
            );
            result.findings.push(finding);
        }
    }
}

// ── Coercion attack surface ─────────────────────────────────────────────────

async fn check_coercion_surface(
    target: &str,
    open_ports: &[u16],
    result: &mut ModuleResult,
) {
    ui::info("Coercion attack surface assessment:");

    // Print Spooler (PrinterBug / SpoolSample)
    if open_ports.contains(&445) {
        // Check if spooler is running by probing the named pipe
        if check_named_pipe(target, "\\spoolss").await {
            ui::warning("Print Spooler (\\spoolss) — SpoolSample/PrinterBug coercion possible");
            let finding = Finding::new(
                "attacks",
                "COERCE-001",
                Severity::High,
                "Print Spooler service accessible (PrinterBug)",
            )
            .with_description(
                "The Print Spooler service is running, enabling SpoolSample/PrinterBug NTLM coercion attacks"
            )
            .with_recommendation("Disable the Print Spooler service on domain controllers and servers that don't need printing")
            .with_mitre("T1187");
            result.findings.push(finding);
        }
    }

    // PetitPotam (MS-EFSRPC)
    if open_ports.contains(&445) || open_ports.contains(&135) {
        if check_named_pipe(target, "\\efsrpc").await
            || check_named_pipe(target, "\\lsarpc").await
        {
            ui::warning("EFS RPC (\\efsrpc/\\lsarpc) — PetitPotam coercion possible");
            let finding = Finding::new(
                "attacks",
                "COERCE-002",
                Severity::High,
                "EFS RPC accessible (PetitPotam)",
            )
            .with_description(
                "MS-EFSRPC endpoints are accessible, enabling PetitPotam NTLM coercion attacks"
            )
            .with_recommendation("Apply MS patches, disable EFS if unused, implement EPA on all services")
            .with_mitre("T1187");
            result.findings.push(finding);
        }
    }

    // DFSCoerce
    if open_ports.contains(&445) {
        if check_named_pipe(target, "\\netdfs").await {
            ui::warning("DFS (\\netdfs) — DFSCoerce coercion possible");
            let finding = Finding::new(
                "attacks",
                "COERCE-003",
                Severity::Medium,
                "DFS Namespace accessible (DFSCoerce)",
            )
            .with_description(
                "DFS Namespace Management pipe is accessible, potentially enabling DFSCoerce NTLM coercion"
            )
            .with_recommendation("Restrict DFS access, implement EPA")
            .with_mitre("T1187");
            result.findings.push(finding);
        }
    }

    // ShadowCoerce
    if open_ports.contains(&445) {
        if check_named_pipe(target, "\\FssagentRpc").await {
            ui::warning("File Server VSS (\\FssagentRpc) — ShadowCoerce possible");
            let finding = Finding::new(
                "attacks",
                "COERCE-004",
                Severity::Medium,
                "File Server VSS Agent accessible (ShadowCoerce)",
            )
            .with_description(
                "VSS Agent RPC is accessible, enabling ShadowCoerce NTLM coercion attacks"
            )
            .with_recommendation("Disable File Server VSS Agent if unused")
            .with_mitre("T1187");
            result.findings.push(finding);
        }
    }
}

/// Check SMB signing configuration via SMB2 Negotiate.
async fn check_smb_signing(target: &str, result: &mut ModuleResult) {
    let addr = format!("{}:445", target);
    let connect = timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await;
    let mut stream = match connect {
        Ok(Ok(s)) => s,
        _ => return,
    };

    let neg_pkt = build_negotiate();
    if stream.write_all(&neg_pkt).await.is_err() {
        return;
    }
    let neg_resp = match smb2_recv(&mut stream).await {
        Ok(r) => r,
        Err(_) => return,
    };
    if smb2_status(&neg_resp) != STATUS_SUCCESS || neg_resp.len() < SMB2_HEADER_LEN + 4 {
        return;
    }

    // SecurityMode is at offset 2-3 in the Negotiate response body (after 64-byte header)
    let sec_mode = if neg_resp.len() > SMB2_HEADER_LEN + 3 {
        u16::from_le_bytes([
            neg_resp[SMB2_HEADER_LEN + 2],
            neg_resp[SMB2_HEADER_LEN + 3],
        ])
    } else {
        return;
    };

    let signing_enabled = sec_mode & 0x01 != 0;
    let signing_required = sec_mode & 0x02 != 0;

    if signing_required {
        ui::success("SMB signing is required");
    } else if signing_enabled {
        ui::warning("SMB signing enabled but NOT required — relay attacks possible");
        let finding = Finding::new(
            "attacks",
            "SMB-SIGN-001",
            Severity::High,
            "SMB signing not required",
        )
        .with_description(
            "SMB signing is enabled but not required. An attacker can relay NTLM authentication to this host for code execution.",
        )
        .with_recommendation(
            "Enable mandatory SMB signing: Set 'Microsoft network server: Digitally sign communications (always)' to Enabled",
        )
        .with_mitre("T1557.001");
        result.findings.push(finding);
    } else {
        ui::warning("SMB signing is DISABLED — relay attacks trivial");
        let finding = Finding::new(
            "attacks",
            "SMB-SIGN-001",
            Severity::High,
            "SMB signing disabled",
        )
        .with_description(
            "SMB signing is completely disabled. NTLM relay attacks to this host are trivial.",
        )
        .with_recommendation(
            "Enable mandatory SMB signing on all domain controllers and servers",
        )
        .with_mitre("T1557.001");
        result.findings.push(finding);
    }

    ui::verbose(&format!(
        "SMB SecurityMode: 0x{:04X} (enabled={}, required={})",
        sec_mode, signing_enabled, signing_required
    ));
}

/// Check if a named pipe is accessible via SMB2.
///
/// Performs a full SMB2 handshake: Negotiate -> Session Setup (anonymous) ->
/// Tree Connect to IPC$ -> Create (open pipe). Returns true if the pipe exists
/// (STATUS_SUCCESS or STATUS_ACCESS_DENIED), false otherwise.
async fn check_named_pipe(target: &str, pipe: &str) -> bool {
    let result = timeout(Duration::from_secs(5), smb2_check_pipe(target, pipe)).await;
    let ok = match result {
        Ok(v) => v,
        Err(_) => {
            ui::verbose(&format!("pipe check {} timed out", pipe));
            false
        }
    };
    ui::verbose(&format!(
        "pipe check {} -> {}",
        pipe,
        if ok { "exists" } else { "not found" }
    ));
    ok
}

// ── SMB2 named-pipe probe helpers ───────────────────────────────────────────

const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
const SMB2_HEADER_LEN: usize = 64;

const CMD_NEGOTIATE: u16 = 0x0000;
const CMD_SESSION_SETUP: u16 = 0x0001;
const CMD_TREE_CONNECT: u16 = 0x0003;
const CMD_CREATE: u16 = 0x0005;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;

/// Build a 64-byte SMB2 header.
fn smb2_header(command: u16, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
    let mut hdr = vec![0u8; SMB2_HEADER_LEN];
    // Signature: \xFESMB
    hdr[0..4].copy_from_slice(SMB2_MAGIC);
    // StructureSize = 64
    hdr[4..6].copy_from_slice(&64u16.to_le_bytes());
    // CreditCharge = 1
    hdr[6..8].copy_from_slice(&1u16.to_le_bytes());
    // Status = 0
    hdr[8..12].copy_from_slice(&0u32.to_le_bytes());
    // Command
    hdr[12..14].copy_from_slice(&command.to_le_bytes());
    // CreditRequest = 31
    hdr[14..16].copy_from_slice(&31u16.to_le_bytes());
    // Flags = 0
    hdr[16..20].copy_from_slice(&0u32.to_le_bytes());
    // NextCommand = 0
    hdr[20..24].copy_from_slice(&0u32.to_le_bytes());
    // MessageId
    hdr[24..32].copy_from_slice(&message_id.to_le_bytes());
    // ProcessId = 0
    hdr[32..36].copy_from_slice(&0u32.to_le_bytes());
    // TreeId
    hdr[36..40].copy_from_slice(&tree_id.to_le_bytes());
    // SessionId
    hdr[40..48].copy_from_slice(&session_id.to_le_bytes());
    // Signature (16 bytes of zero, no signing)
    hdr
}

/// Wrap an SMB2 message in a NetBIOS session header (4 bytes, big-endian length).
fn netbios_wrap(smb_msg: &[u8]) -> Vec<u8> {
    let len = smb_msg.len() as u32;
    let mut pkt = Vec::with_capacity(4 + smb_msg.len());
    pkt.push(0); // NetBIOS session message type
    pkt.push(((len >> 16) & 0xFF) as u8);
    pkt.push(((len >> 8) & 0xFF) as u8);
    pkt.push((len & 0xFF) as u8);
    pkt.extend_from_slice(smb_msg);
    pkt
}

/// Build an SMB2 Negotiate request (dialect 0x0202).
fn build_negotiate() -> Vec<u8> {
    let mut hdr = smb2_header(CMD_NEGOTIATE, 0, 0, 0);
    // Negotiate body: StructureSize=36, DialectCount=1, SecurityMode=1 (signing enabled),
    // Reserved=0, Capabilities=0, ClientGuid=0, ClientStartTime=0, Dialects=[0x0202]
    let mut body = vec![0u8; 36 + 2]; // 36-byte struct + 2-byte dialect
    // StructureSize = 36
    body[0..2].copy_from_slice(&36u16.to_le_bytes());
    // DialectCount = 1
    body[2..4].copy_from_slice(&1u16.to_le_bytes());
    // SecurityMode = 1 (signing enabled)
    body[4..6].copy_from_slice(&1u16.to_le_bytes());
    // Reserved (2 bytes) = 0 — already zero
    // Capabilities (4 bytes) = 0 — already zero
    // ClientGuid (16 bytes) = 0 — already zero
    // ClientStartTime (8 bytes) = 0 — already zero
    // Dialect 0x0202
    body[36..38].copy_from_slice(&0x0202u16.to_le_bytes());
    hdr.extend_from_slice(&body);
    netbios_wrap(&hdr)
}

/// Minimal NTLMSSP_NEGOTIATE blob for anonymous/null session setup.
fn ntlmssp_negotiate_blob() -> Vec<u8> {
    // GSS-API / SPNEGO wrapper around NTLMSSP_NEGOTIATE
    // This is a minimal ASN.1/DER wrapper that Windows accepts.
    let ntlmssp: Vec<u8> = vec![
        // NTLMSSP signature
        b'N', b'T', b'L', b'M', b'S', b'S', b'P', 0x00,
        // Type 1 (Negotiate)
        0x01, 0x00, 0x00, 0x00,
        // Flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM
        0x97, 0x82, 0x08, 0xe2,
        // DomainNameFields (Len, MaxLen, Offset) = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // WorkstationFields (Len, MaxLen, Offset) = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Wrap in SPNEGO / GSS-API
    let mech_oid: Vec<u8> = vec![
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
        0x37, 0x02, 0x02, 0x0a, // OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
    ];

    // mechToken wrapper
    let mech_token_inner_len = ntlmssp.len();
    let mut mech_token = vec![0xa2];
    der_push_length(&mut mech_token, 2 + mech_token_inner_len);
    mech_token.push(0x04);
    der_push_length(&mut mech_token, mech_token_inner_len);
    mech_token.extend_from_slice(&ntlmssp);

    // mechTypes wrapper (SEQUENCE OF OID)
    let mut mech_types_inner = Vec::new();
    mech_types_inner.extend_from_slice(&mech_oid);
    let mut mech_types = vec![0xa0];
    der_push_length(&mut mech_types, 2 + mech_types_inner.len());
    mech_types.push(0x30);
    der_push_length(&mut mech_types, mech_types_inner.len());
    mech_types.extend_from_slice(&mech_types_inner);

    // negTokenInit (SEQUENCE)
    let seq_payload_len = mech_types.len() + mech_token.len();
    let mut neg_token_init = vec![0x30];
    der_push_length(&mut neg_token_init, seq_payload_len);
    neg_token_init.extend_from_slice(&mech_types);
    neg_token_init.extend_from_slice(&mech_token);

    // context [0] wrapper
    let mut ctx = vec![0xa0];
    der_push_length(&mut ctx, neg_token_init.len());
    ctx.extend_from_slice(&neg_token_init);

    // APPLICATION [0] (GSS-API)
    let spnego_oid: Vec<u8> = vec![
        0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // OID 1.3.6.1.5.5.2 (SPNEGO)
    ];
    let app_payload_len = spnego_oid.len() + ctx.len();
    let mut gss = vec![0x60];
    der_push_length(&mut gss, app_payload_len);
    gss.extend_from_slice(&spnego_oid);
    gss.extend_from_slice(&ctx);

    gss
}

/// Push a DER length encoding.
fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// Build an SMB2 Session Setup request with an NTLMSSP_NEGOTIATE token.
fn build_session_setup(message_id: u64, security_blob: &[u8]) -> Vec<u8> {
    let mut hdr = smb2_header(CMD_SESSION_SETUP, message_id, 0, 0);
    // Session Setup body: StructureSize=25, Flags=0, SecurityMode=1, Capabilities=0,
    // Channel=0, SecurityBufferOffset, SecurityBufferLength, PreviousSessionId=0
    let buf_offset: u16 = (SMB2_HEADER_LEN + 24) as u16; // body is 24 bytes (25 struct, padded)
    let buf_len: u16 = security_blob.len() as u16;
    let mut body = vec![0u8; 24];
    // StructureSize = 25
    body[0..2].copy_from_slice(&25u16.to_le_bytes());
    // Flags = 0
    body[2] = 0;
    // SecurityMode = 1
    body[3] = 1;
    // Capabilities = 0 (4 bytes at offset 4)
    // Channel = 0 (4 bytes at offset 8)
    // SecurityBufferOffset
    body[12..14].copy_from_slice(&buf_offset.to_le_bytes());
    // SecurityBufferLength
    body[14..16].copy_from_slice(&buf_len.to_le_bytes());
    // PreviousSessionId = 0 (8 bytes at offset 16)
    hdr.extend_from_slice(&body);
    hdr.extend_from_slice(security_blob);
    netbios_wrap(&hdr)
}

/// Build an SMB2 Tree Connect request to \\target\IPC$.
fn build_tree_connect(message_id: u64, session_id: u64, target: &str) -> Vec<u8> {
    let path = format!("\\\\{}\\IPC$", target);
    let path_utf16: Vec<u8> = path
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hdr = smb2_header(CMD_TREE_CONNECT, message_id, session_id, 0);
    // Tree Connect body: StructureSize=9, Reserved=0, PathOffset, PathLength
    let buf_offset: u16 = (SMB2_HEADER_LEN + 8) as u16; // 8 bytes of body before path
    let buf_len: u16 = path_utf16.len() as u16;
    let mut body = vec![0u8; 8];
    // StructureSize = 9
    body[0..2].copy_from_slice(&9u16.to_le_bytes());
    // Reserved = 0 (2 bytes)
    // PathOffset
    body[4..6].copy_from_slice(&buf_offset.to_le_bytes());
    // PathLength
    body[6..8].copy_from_slice(&buf_len.to_le_bytes());
    hdr.extend_from_slice(&body);
    hdr.extend_from_slice(&path_utf16);
    netbios_wrap(&hdr)
}

/// Build an SMB2 Create request to open a named pipe.
fn build_create(message_id: u64, session_id: u64, tree_id: u32, pipe_name: &str) -> Vec<u8> {
    let name_utf16: Vec<u8> = pipe_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hdr = smb2_header(CMD_CREATE, message_id, session_id, tree_id);
    // Create request body: StructureSize=57, then fields
    // Total fixed body = 56 bytes (StructureSize says 57 but last byte is part of Buffer)
    let name_offset: u16 = (SMB2_HEADER_LEN + 56) as u16;
    let name_length: u16 = name_utf16.len() as u16;

    let mut body = vec![0u8; 56];
    // StructureSize = 57
    body[0..2].copy_from_slice(&57u16.to_le_bytes());
    // SecurityFlags = 0 (byte 2)
    // RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE (byte 3) = 0
    // ImpersonationLevel = Impersonation (4 bytes at offset 4) = 2
    body[4..8].copy_from_slice(&2u32.to_le_bytes());
    // SmbCreateFlags (8 bytes at offset 8) = 0
    // Reserved (8 bytes at offset 16) = 0
    // DesiredAccess (4 bytes at offset 24): FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES
    body[24..28].copy_from_slice(&0x0012_0089u32.to_le_bytes());
    // FileAttributes (4 bytes at offset 28) = 0
    // ShareAccess (4 bytes at offset 32): FILE_SHARE_READ | FILE_SHARE_WRITE
    body[32..36].copy_from_slice(&0x0000_0003u32.to_le_bytes());
    // CreateDisposition (4 bytes at offset 36): FILE_OPEN = 1
    body[36..40].copy_from_slice(&1u32.to_le_bytes());
    // CreateOptions (4 bytes at offset 40) = 0
    // NameOffset (2 bytes at offset 44)
    body[44..46].copy_from_slice(&name_offset.to_le_bytes());
    // NameLength (2 bytes at offset 46)
    body[46..48].copy_from_slice(&name_length.to_le_bytes());
    // CreateContextsOffset (4 bytes at offset 48) = 0
    // CreateContextsLength (4 bytes at offset 52) = 0
    hdr.extend_from_slice(&body);
    hdr.extend_from_slice(&name_utf16);
    netbios_wrap(&hdr)
}

/// Read a full SMB2 response (NetBIOS framed), return the raw SMB2 message.
async fn smb2_recv(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    // Read 4-byte NetBIOS header
    let mut nb_hdr = [0u8; 4];
    stream.read_exact(&mut nb_hdr).await?;
    let msg_len = ((nb_hdr[1] as usize) << 16)
        | ((nb_hdr[2] as usize) << 8)
        | (nb_hdr[3] as usize);
    if msg_len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SMB2 response too large",
        ));
    }
    let mut buf = vec![0u8; msg_len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Extract NT Status from an SMB2 response (bytes 8..12).
fn smb2_status(resp: &[u8]) -> u32 {
    if resp.len() < 12 {
        return 0xFFFF_FFFF;
    }
    u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]])
}

/// Extract Session ID from an SMB2 response (bytes 40..48).
fn smb2_session_id(resp: &[u8]) -> u64 {
    if resp.len() < 48 {
        return 0;
    }
    u64::from_le_bytes(resp[40..48].try_into().unwrap_or([0u8; 8]))
}

/// Extract Tree ID from an SMB2 response (bytes 36..40).
fn smb2_tree_id(resp: &[u8]) -> u32 {
    if resp.len() < 40 {
        return 0;
    }
    u32::from_le_bytes(resp[36..40].try_into().unwrap_or([0u8; 4]))
}

/// Perform the full SMB2 pipe-existence check.
async fn smb2_check_pipe(target: &str, pipe: &str) -> bool {
    // Strip leading backslashes from pipe name
    let pipe_name = pipe.trim_start_matches('\\');

    let addr = format!("{}:445", target);
    let mut stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            ui::verbose(&format!("SMB connect to {} failed: {}", addr, e));
            return false;
        }
    };

    // Step 1: SMB2 Negotiate
    let neg_pkt = build_negotiate();
    if stream.write_all(&neg_pkt).await.is_err() {
        return false;
    }
    let neg_resp = match smb2_recv(&mut stream).await {
        Ok(r) => r,
        Err(_) => return false,
    };
    let status = smb2_status(&neg_resp);
    if status != STATUS_SUCCESS {
        ui::verbose(&format!("SMB2 Negotiate failed: 0x{:08X}", status));
        return false;
    }

    // Step 2: Session Setup (NTLMSSP Negotiate — anonymous)
    let security_blob = ntlmssp_negotiate_blob();
    let setup_pkt = build_session_setup(1, &security_blob);
    if stream.write_all(&setup_pkt).await.is_err() {
        return false;
    }
    let setup_resp = match smb2_recv(&mut stream).await {
        Ok(r) => r,
        Err(_) => return false,
    };
    let status = smb2_status(&setup_resp);
    let session_id = smb2_session_id(&setup_resp);

    // Accept STATUS_SUCCESS (null session granted) or STATUS_MORE_PROCESSING_REQUIRED
    // (NTLM challenge). For anonymous access we try to proceed either way.
    if status == STATUS_MORE_PROCESSING_REQUIRED {
        // Send a second Session Setup with an empty NTLMSSP_AUTH to complete null session
        let null_auth = build_session_setup_null_auth(2, session_id);
        if stream.write_all(&null_auth).await.is_err() {
            return false;
        }
        let auth_resp = match smb2_recv(&mut stream).await {
            Ok(r) => r,
            Err(_) => return false,
        };
        let auth_status = smb2_status(&auth_resp);
        if auth_status != STATUS_SUCCESS && auth_status != STATUS_ACCESS_DENIED {
            ui::verbose(&format!("SMB2 Session Setup auth failed: 0x{:08X}", auth_status));
            // Even if session setup returns access denied, we can't proceed
            if auth_status == STATUS_ACCESS_DENIED {
                // Some servers deny null sessions entirely — pipe existence unknown
                return false;
            }
            return false;
        }
    } else if status != STATUS_SUCCESS {
        ui::verbose(&format!("SMB2 Session Setup failed: 0x{:08X}", status));
        return false;
    }

    // Step 3: Tree Connect to IPC$
    let tc_pkt = build_tree_connect(3, session_id, target);
    if stream.write_all(&tc_pkt).await.is_err() {
        return false;
    }
    let tc_resp = match smb2_recv(&mut stream).await {
        Ok(r) => r,
        Err(_) => return false,
    };
    let status = smb2_status(&tc_resp);
    if status != STATUS_SUCCESS {
        ui::verbose(&format!("SMB2 Tree Connect to IPC$ failed: 0x{:08X}", status));
        return false;
    }
    let tree_id = smb2_tree_id(&tc_resp);

    // Step 4: Create (open named pipe)
    let create_pkt = build_create(4, session_id, tree_id, pipe_name);
    if stream.write_all(&create_pkt).await.is_err() {
        return false;
    }
    let create_resp = match smb2_recv(&mut stream).await {
        Ok(r) => r,
        Err(_) => return false,
    };
    let status = smb2_status(&create_resp);
    ui::verbose(&format!(
        "SMB2 Create pipe '{}' status: 0x{:08X}",
        pipe_name, status
    ));

    // Pipe exists if we got SUCCESS or ACCESS_DENIED
    status == STATUS_SUCCESS || status == STATUS_ACCESS_DENIED
}

/// Build a second Session Setup request with an empty/null NTLMSSP_AUTH blob
/// to complete a null/anonymous session after receiving an NTLM challenge.
fn build_session_setup_null_auth(message_id: u64, session_id: u64) -> Vec<u8> {
    // Minimal NTLMSSP_AUTH with empty fields (anonymous logon)
    let ntlmssp_auth: Vec<u8> = vec![
        // NTLMSSP signature
        b'N', b'T', b'L', b'M', b'S', b'S', b'P', 0x00,
        // Type 3 (Authenticate)
        0x03, 0x00, 0x00, 0x00,
        // LmChallengeResponseFields (Len=0, MaxLen=0, Offset=0)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // NtChallengeResponseFields (Len=0, MaxLen=0, Offset=0)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // DomainNameFields (Len=0, MaxLen=0, Offset=0)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // UserNameFields (Len=0, MaxLen=0, Offset=0)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // WorkstationFields (Len=0, MaxLen=0, Offset=0)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // EncryptedRandomSessionKeyFields (Len=0, MaxLen=0, Offset=0)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // NegotiateFlags
        0x15, 0x82, 0x08, 0xa0,
    ];

    // Wrap in SPNEGO negTokenResp (context class 1)
    // responseToken [2]
    let mut resp_token = vec![0xa2];
    der_push_length(&mut resp_token, 2 + ntlmssp_auth.len());
    resp_token.push(0x04);
    der_push_length(&mut resp_token, ntlmssp_auth.len());
    resp_token.extend_from_slice(&ntlmssp_auth);

    // negTokenResp SEQUENCE
    let mut neg_token_resp = vec![0x30];
    der_push_length(&mut neg_token_resp, resp_token.len());
    neg_token_resp.extend_from_slice(&resp_token);

    // context [1] wrapper
    let mut ctx = vec![0xa1];
    der_push_length(&mut ctx, neg_token_resp.len());
    ctx.extend_from_slice(&neg_token_resp);

    let mut hdr = smb2_header(CMD_SESSION_SETUP, message_id, session_id, 0);
    let buf_offset: u16 = (SMB2_HEADER_LEN + 24) as u16;
    let buf_len: u16 = ctx.len() as u16;
    let mut body = vec![0u8; 24];
    body[0..2].copy_from_slice(&25u16.to_le_bytes());
    body[3] = 1; // SecurityMode = 1
    body[12..14].copy_from_slice(&buf_offset.to_le_bytes());
    body[14..16].copy_from_slice(&buf_len.to_le_bytes());
    hdr.extend_from_slice(&body);
    hdr.extend_from_slice(&ctx);
    netbios_wrap(&hdr)
}

// ── WebDAV check ────────────────────────────────────────────────────────────

async fn check_webdav(target: &str, ports: &[u16], result: &mut ModuleResult) {
    for port in ports {
        let response = http_probe(target, *port, "/").await;
        if let Ok(resp) = response {
            let has_dav = resp.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("dav"));
            let allows_propfind = resp
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("allow") && v.contains("PROPFIND"));

            if has_dav || allows_propfind {
                ui::warning(&format!("WebDAV detected on port {}", port));
                let finding = Finding::new(
                    "attacks",
                    "WEBDAV-001",
                    Severity::Medium,
                    &format!("WebDAV service on port {}", port),
                )
                .with_description("WebDAV can be leveraged for NTLM relay and coercion attacks")
                .with_recommendation("Disable WebDAV if not required; ensure NTLM relay protections are in place")
                .with_mitre("T1557.001");
                result.findings.push(finding);
            }
        }
    }
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

struct ProbeResponse {
    status: u16,
    headers: Vec<(String, String)>,
}

async fn http_probe(target: &str, port: u16, path: &str) -> Result<ProbeResponse> {
    let addr = format!("{}:{}", target, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await??;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: aydee/2.0\r\nConnection: close\r\n\r\n",
        path, target
    );
    timeout(Duration::from_secs(3), stream.write_all(req.as_bytes())).await??;

    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n == 0 {
        anyhow::bail!("empty response");
    }

    let resp = String::from_utf8_lossy(&buf[..n]);
    Ok(ProbeResponse {
        status: parse_status(&resp).unwrap_or(0),
        headers: extract_headers(&resp),
    })
}

async fn https_probe(target: &str, port: u16, path: &str) -> Result<ProbeResponse> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()?;

    let url = format!("https://{}:{}{}", target, port, path);
    let response = client
        .get(&url)
        .header("User-Agent", "aydee/2.0")
        .send()
        .await?;

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    Ok(ProbeResponse { status, headers })
}

fn parse_status(resp: &str) -> Option<u16> {
    resp.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn extract_headers(resp: &str) -> Vec<(String, String)> {
    resp.lines()
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}
