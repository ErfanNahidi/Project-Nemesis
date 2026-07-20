# avlab — AV/EDR Validation Lab Runbook

## When to use which method

```
Defender catches the loader?
        │
        ▼
Run bisect first
        │
        ├─ CONVERGED (byte offset found)
        │       └─ Static signature → byte-patch or strip that region
        │
        └─ INCONCLUSIVE (every prefix still detects)
                └─ ML / cloud-reputation detection
                        └─ Run toggle ablation
                                │
                                ├─ One toggle flips DETECTED → CLEAN
                                │       └─ That layer is the ML feature
                                │
                                └─ No single toggle bypasses
                                        └─ Combination needed → pair/triplet ablation
```

## Bisect — find a static byte signature

```bash
# Inside adscan-lite-dev:edge container
cd /opt/adscan/adscan-src/tools

python -m avlab bisect \
  --binary /opt/payloads/adscan_loader_baseline.exe \
  --scanner defender \
  --scanner-host 192.168.180.22 \
  --scanner-domain north.sevenkingdoms.local \
  --scanner-user jon.snow \
  --scanner-password iknownothing
```

Outputs:
- `SIGNATURE BOUNDARY: offset 0xXXXX` — the bad bytes end here
- Hex dump of the trailing 256 bytes — the signature likely sits in this window
- `INCONCLUSIVE` — no static signature; switch to toggle ablation

## Toggle ablation — identify which OPSEC layer the ML model keys on

```bash
python -m avlab ablate \
  --catalog catalogs/adscan_loader.yaml \
  --payload /opt/payloads/GodPotato-NET4.exe \
  --payload-args "" \
  --scanner defender \
  --scanner-host 192.168.180.22 \
  --scanner-domain north.sevenkingdoms.local \
  --scanner-user jon.snow \
  --scanner-password iknownothing
```

This:
1. Builds one `adscan_loader.exe` per variant (14 variants in the default catalog)
2. Scans each with Defender via MpCmdRun on the target
3. Writes `tools/avlab/runs/<run_id>/matrix.json` + `matrix.md`

## Reading the matrix.md output

| Verdict | Meaning |
|---|---|
| ✅ clean | Defender did not detect this variant |
| ❌ detected | Detected; threat names in the Threats column |
| 🚫 upload-blocked | Real-time protection blocked the upload (on-write detection) |
| ⚠️ inconclusive | Scanner returned neither clean nor threat; check scanner log |

**Example: ETW + AMSI patches are the ML features**

```
baseline              all layers on        ❌ detected   Trojan:Win64/AsyncRat.RPY!MTB
no_etw_patch          no ETW patch         ❌ detected   ...
no_amsi_patch         no AMSI patch        ❌ detected   ...
no_etw_no_amsi        both removed         ✅ clean
```

→ The model keys on the combination of both patches. Removing either one alone
  is not enough. A v2 loader that implements these patches differently (or
  moves them into shellcode context) will likely bypass.

## Adding a new scanner (CrowdStrike, S1, AMSI)

1. Create `scanners/<name>.py` implementing the `Scanner` protocol:
   - `name: str` attribute
   - `setup(self) -> None`
   - `scan(self, request: ScanRequest) -> ScanResult`
   - `teardown(self) -> None`

2. Register in `scanners/registry.py`:
   ```python
   def _crowdstrike_factory(config, workspace):
       from avlab.scanners.crowdstrike import CrowdStrikeScanner, CSTarget
       return CrowdStrikeScanner(CSTarget(**config), workspace)

   register("crowdstrike", _crowdstrike_factory)
   ```

3. Run: `--scanner crowdstrike --scanner-host ... --scanner-api-key ...`

## Run history

All runs persist under `tools/avlab/runs/<run_id>/`. Never overwrite —
the history is what makes month-over-month drift analysis possible.

```
tools/avlab/runs/
└── adscan_loader_20250503T142301Z/
    ├── matrix.json          ← machine-readable, versioned schema
    ├── matrix.md            ← human-readable digest
    ├── variants/
    │   ├── adscan_loader_baseline/
    │   │   └── adscan_loader_baseline.exe
    │   └── adscan_loader_no_etw_no_amsi/
    │       └── ...
    └── scanner_logs/
        ├── adscan_loader_baseline__defender.log
        └── ...
```
