"""Catalog of AV/EDR products ADscan detects via aiosmb.

Source of truth: kept in sync with NetExec's ``enum_av`` module
(https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/enum_av.py),
which itself derives from @an0n_r0's serviceDetector. We use the same
service names and pipe patterns so a target detected by ``nxc -M enum_av``
is also detected by ADscan.

Differences from NXC:
  - Detection transport is registry-probe (RRP) on the service key, not
    ``LsarLookupNames`` over LSARPC.  RRP requires RemoteRegistry up but
    yields the ``Start`` DWORD (auto/manual/disabled) for the activity
    classifier; LSARPC only confirms presence.
  - Pipe matching is substring-based (case-insensitive) rather than glob.
    Patterns are stored as the most distinctive prefix/segment of NXC's
    glob; e.g. ``aswCallbackPipe*`` -> ``aswCallbackPipe``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProductSignature:
    """Detection signature for one AV/EDR product.

    Attributes:
        name: Display name.
        category: ``"av"`` or ``"edr"``.
        service_keys: Subkeys under
            ``HKLM\\SYSTEM\\CurrentControlSet\\Services`` to probe.
        pipe_patterns: Substrings matched (case-insensitive) against
            IPC$ pipe names.
    """

    name: str
    category: str
    service_keys: tuple[str, ...]
    pipe_patterns: tuple[str, ...]


PRODUCT_CATALOG: tuple[ProductSignature, ...] = (
    ProductSignature(
        name="Acronis Cyber Protect",
        category="edr",
        service_keys=("AcronisActiveProtectionService",),
        pipe_patterns=(),
    ),
    ProductSignature(
        name="Avast / AVG",
        category="av",
        service_keys=(
            "AvastWscReporter",
            "aswbIDSAgent",
            "AVGWscReporter",
            "avgbIDSAgent",
        ),
        pipe_patterns=("aswCallbackPipe", "avgCallbackPipe"),
    ),
    ProductSignature(
        name="Bitdefender",
        category="av",
        service_keys=(
            # Consumer edition
            "BDLDaemon",
            "BDAuxSrv",
            "BDVEDISK",
            "UPDATESRV",
            "VSSERV",
            "bdredline",
            "bdredline_agent",
            # GravityZone / Endpoint Security Tools (enterprise)
            "EPRedline",
            "EPUpdateService",
            "EPSecurityService",
            "EPProtectedService",
            "EPIntegrationService",
        ),
        pipe_patterns=(
            "bdConnector",
            "etw_sensor_pipe_ppl",
            "bdagent",
            "bd.process.broker.pipe",
            "bdauxsrv",
            "antitracker.low",
            "aspam.actions",
        ),
    ),
    ProductSignature(
        name="Carbon Black App Control",
        category="edr",
        service_keys=("Parity",),
        pipe_patterns=(),
    ),
    ProductSignature(
        name="Carbon Black EDR",
        category="edr",
        service_keys=("CbDefense", "CbDefenseSensor", "carbonblack"),
        pipe_patterns=("carbonblack",),
    ),
    ProductSignature(
        name="Check Point Endpoint Security",
        category="av",
        service_keys=("CPDA", "vsmon", "CPFileAnlyz", "EPClientUIService"),
        pipe_patterns=(),
    ),
    ProductSignature(
        name="Cortex XDR",
        category="edr",
        service_keys=("cyserver", "cyvera", "xdrhealth"),
        pipe_patterns=("cyserver",),
    ),
    ProductSignature(
        name="CrowdStrike Falcon",
        category="edr",
        service_keys=("CSAgent", "CSFalconService"),
        pipe_patterns=("crowdstrike", "csagent"),
    ),
    ProductSignature(
        name="Cybereason",
        category="edr",
        service_keys=("CybereasonActiveProbe", "CybereasonCRS", "CybereasonBlocki"),
        pipe_patterns=(
            "CybereasonAPConsoleMinionHostIpc_",
            "CybereasonAPServerProxyIpc_",
        ),
    ),
    ProductSignature(
        name="Cylance",
        category="edr",
        service_keys=("CylanceSvc",),
        pipe_patterns=("Cylance",),
    ),
    ProductSignature(
        name="Elastic Endpoint",
        category="edr",
        service_keys=("Elastic Agent", "ElasticEndpoint"),
        pipe_patterns=("ElasticEndpointServiceComms-", "elastic-agent-system"),
    ),
    ProductSignature(
        name="ESET",
        category="av",
        service_keys=(
            "ekrn",
            "ekm",
            "epfw",
            "epfwlwf",
            "epfwwfp",
            "EraAgentSvc",
            "ERAAgent",
            "efwd",
            "ehttpsrv",
            "EHttpSrv",
        ),
        pipe_patterns=("ekrn", "nod_scriptmon_pipe"),
    ),
    ProductSignature(
        name="F-Secure / WithSecure",
        category="av",
        service_keys=(
            "F-Secure Gatekeeper",
            "FSMA",
            "fsdevcon",
            "fshoster",
            "fsnethoster",
            "fsulhoster",
            "fsulnethoster",
            "fsulprothoster",
            "wsulavprohoster",
        ),
        pipe_patterns=("FSMA", "FS_CCFIPC_"),
    ),
    ProductSignature(
        name="FortiClient",
        category="av",
        service_keys=("FA_Scheduler", "FCT_SecSvr"),
        pipe_patterns=("FortiClient_DBLogDaemon", "FC_"),
    ),
    ProductSignature(
        name="FortiEDR",
        category="edr",
        service_keys=("FortiEDR Collector Service",),
        pipe_patterns=(),
    ),
    ProductSignature(
        name="G DATA Security Client",
        category="av",
        service_keys=("AVKWCtl", "AVKProxy", "GDScan"),
        pipe_patterns=("exploitProtectionIPC",),
    ),
    ProductSignature(
        name="HarfangLab EDR",
        category="edr",
        service_keys=(
            "hurukai",
            "Hurukai agent",
            "HarfangLab Hurukai agent",
            "hurukai-av",
            "hurukai-ui",
        ),
        pipe_patterns=("hurukai-control", "hurukai-servicing", "hurukai-amsi"),
    ),
    ProductSignature(
        name="Ivanti Security",
        category="av",
        service_keys=("STAgent$Shavlik Protect", "STDispatch$Shavlik Protect"),
        pipe_patterns=(),
    ),
    ProductSignature(
        name="Kaseya Agent Endpoint",
        category="av",
        service_keys=("KAENDKSAASC", "KAKSAASC"),
        pipe_patterns=("kaseyaUserKSA", "kaseyaAgentKSA"),
    ),
    ProductSignature(
        name="Kaspersky",
        category="av",
        service_keys=(
            "AVP",
            "klif",
            "kl1",
            "kavfsslp",
            "KAVFS",
            "KAVFSGT",
            "klnagent",
        ),
        pipe_patterns=("AVP", "Exploit_Blocker"),
    ),
    ProductSignature(
        name="Malwarebytes",
        category="av",
        service_keys=("MBAMService", "MBEndpointAgent"),
        pipe_patterns=("MBLG", "MBEA2_R", "MBEA2_W"),
    ),
    ProductSignature(
        name="McAfee / Trellix EDR",
        category="edr",
        service_keys=(
            "mfefire",
            "McAfeeFramework",
            "mfehidk",
            "McAfee Endpoint Security Platform Service",
            "mfemactl",
            "mfemms",
            "masvc",
            "macmnsvc",
            "mfetp",
            "mfewc",
            "mfeaack",
        ),
        pipe_patterns=(
            "TrellixEDR_Pipe_",
            "mfemactl_",
            "mfefire_",
            "McAfeeAgent_Pipe_",
            "mfetp_",
            "mfehidk",
        ),
    ),
    ProductSignature(
        name="Palo Alto Cortex",
        category="edr",
        service_keys=("cyserver", "cyvera"),
        pipe_patterns=("cyserver",),
    ),
    ProductSignature(
        name="Panda Adaptive Defense 360",
        category="av",
        service_keys=("PandaAetherAgent", "PSUAService", "NanoServiceMain"),
        pipe_patterns=("NNS_API_IPC_SRV_ENDPOINT", "PSANMSrvcPpal"),
    ),
    ProductSignature(
        name="Rapid7 Insight",
        category="edr",
        service_keys=("ir_agent",),
        pipe_patterns=(),
    ),
    ProductSignature(
        name="SentinelOne",
        category="edr",
        service_keys=(
            "SentinelAgent",
            "SentinelHelperService",
            "SentinelStaticEngine",
            "LogProcessorService",
        ),
        pipe_patterns=(
            "SentinelAgent",
            "SentinelAgentWorkerCert.",
            "DFIScanner.Etw.",
            "DFIScanner.Inline.",
        ),
    ),
    ProductSignature(
        name="Sophos Intercept X",
        category="av",
        service_keys=(
            "SntpService",
            "Sophos Endpoint Defense Service",
            "Sophos File Scanner Service",
            "Sophos Health Service",
            "Sophos Live Query",
            "Sophos Managed Threat Response",
            "Sophos MCS Agent",
            "Sophos MCS Client",
            "Sophos System Protection Service",
            "SAVService",
            "SophosAV",
        ),
        pipe_patterns=(
            "SophosUI",
            "SophosEventStore",
            "sophos_deviceencryption",
            "sophoslivequery_",
            "Sophos",
        ),
    ),
    ProductSignature(
        name="Symantec / Norton",
        category="av",
        service_keys=(
            "SepMasterService",
            "SepScanService",
            "SNAC",
            "Symantec AntiVirus",
            "NAVENG",
        ),
        pipe_patterns=("Symantec",),
    ),
    ProductSignature(
        name="Trend Micro Endpoint Security",
        category="av",
        service_keys=(
            "TmCCSF",
            "TMBMServer",
            "ntrtscan",
            "Trend Micro Endpoint Basecamp",
            "Trend Micro Web Service Communicator",
            "TMiACAgentSvc",
            "CETASvc",
            "iVPAgent",
            "ds_agent",
            "ds_monitor",
            "ds_notifier",
        ),
        pipe_patterns=(
            "IPC_XBC_XBC_AGENT_PIPE_",
            "iacagent_",
            "OIPC_LWCS_PIPE_",
            "Log_ServerNamePipe",
            "OIPC_NTRTSCAN_PIPE_",
            "TrendMicro",
        ),
    ),
    ProductSignature(
        name="Windows Defender",
        category="av",
        # Sense = Windows Defender ATP / MDE — when present, treat as EDR-grade.
        service_keys=("WinDefend", "WdNisSvc", "WdFilter", "Sense"),
        pipe_patterns=("MsMpEng",),
    ),
)


# Registry constants used by the fingerprint service.
SERVICES_BASE = r"HKLM\SYSTEM\CurrentControlSet\Services"
DEFENDER_RTP_KEY = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
DEFENDER_RTP_VAL = "DisableRealtimeMonitoring"


__all__ = [
    "ProductSignature",
    "PRODUCT_CATALOG",
    "SERVICES_BASE",
    "DEFENDER_RTP_KEY",
    "DEFENDER_RTP_VAL",
]
