# ConfigMgr BIOS Compliance Checker — Documentation

**Version:** 1.11 · **Platform:** ConfigMgr / SCCM · **Language:** English

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Requirements](#2-requirements)
3. [Step 1 — Export Device Data](#3-step-1--export-device-data)
   - [Option A — PowerShell Export (recommended)](#option-a--powershell-export-recommended)
   - [CSP Version — HP SBKPFV3 Readiness](#csp-version--hp-sbkpfv3-readiness-optional)
   - [Option B — SSRS Export](#option-b--ssrs-export)
4. [Step 2 — Load & Analyse](#4-step-2--load--analyse)
   - [JSON Import](#json-import-powershell-export)
   - [CSV Import](#csv-import-ssrs-export)
5. [Step 3 — Secure Boot Import (optional)](#5-step-3--secure-boot-import-optional)
6. [Results & Filters](#6-results--filters)
7. [Export](#7-export)
   - [CSV](#csv)
   - [HTML Report](#html-report)
   - [PDF / Print](#pdf--print)
8. [BIOS Database](#8-bios-database)
   - [Model Matching](#model-matching)
   - [Lenovo Machine Type Lookup](#lenovo-machine-type-code-lookup)
   - [Version Normalization](#bios-version-normalization)
   - [Version Comparison](#version-comparison)
9. [VM Exclusion](#9-vm-exclusion)
10. [Status Codes](#10-status-codes)
11. [Changelog](#11-changelog)

---

## 1. Introduction

The ConfigMgr BIOS Compliance Checker is a self-contained HTML tool that identifies devices in your Microsoft Endpoint Configuration Manager (MECM / SCCM) environment whose BIOS version does not meet the minimum requirement for the **Secure Boot 2023 UEFI certificate update**.

Devices that receive the Windows Update carrying the new Secure Boot certificate without a sufficiently recent BIOS may fail to boot. The tool checks your entire ConfigMgr device inventory against vendor-published minimum versions in seconds. Virtual machines are automatically excluded.

> **No server-side component required.** The tool runs entirely in the browser — no agent, no backend, no network connection at runtime.

### How it works

1. Export hardware inventory data from ConfigMgr using the PowerShell script or an SSRS report.
2. Load the exported `.json` or `.csv` file into the tool.
3. The tool matches each device's model against the built-in BIOS database and compares installed vs minimum version. VMs are excluded automatically.
4. Results appear in a filterable, sortable table with summary tiles. Non-compliant devices sort to the top.

### Compared to the Intune tool

| Feature | ConfigMgr Tool | Intune Tool |
|---|---|---|
| Data source | PowerShell / SSRS export | Graph API / CSV export |
| Auth required at runtime | No — file-based | Yes (Graph) / No (CSV) |
| Lenovo model identification | Product name (WMI) + MT code fallback | 4-char machine type code primary |
| Secure Boot column | Optional (Step 3 CSV) | Optional (CSV) |
| HP SBKPFV3 readiness | Optional (CSP Version field) | Not available |
| Last HW Scan column | ✓ Included | Not available |
| VM auto-exclusion | ✓ Hyper-V + VMware | Not applicable |
| BIOS DB | Identical (651 Lenovo + Dell + HP) | Identical |

---

## 2. Requirements

| Component | Requirement |
|---|---|
| Browser | Any modern browser (Chrome, Edge, Firefox, Safari). |
| ConfigMgr permissions (PowerShell) | Read-Only Analyst role or equivalent SQL read. Required views: `v_R_System`, `v_GS_COMPUTER_SYSTEM`, `v_GS_PC_BIOS`, `v_GS_WORKSTATION_STATUS`. Optional: `v_GS_COMPUTER_SYSTEM_PRODUCT` (HP SBKPFV3). |
| ConfigMgr permissions (SSRS) | Report Users security role. |
| Hardware Inventory | Must be enabled and devices must have reported at least once. |

> **⚠️ Data quality:** Devices without recent Hardware Inventory will appear as *Not Checked*. Check the **Last HW Scan** column — dates older than 30 days may indicate stale data.

---

## 3. Step 1 — Export Device Data

The tool accepts **JSON** (PowerShell export) and **CSV** (SSRS or tabular export).

### Option A — PowerShell Export (recommended)

Run this script on any machine with SQL read access to the ConfigMgr database. It auto-detects whether `Win32_ComputerSystemProduct` is enabled and conditionally includes the CSP Version field.

```powershell
# ConfigMgr BIOS Export Script — v1.10
# Requires: Read-Only Analyst role or equivalent SQL read permissions

param(
  [string]$SiteServer  = "CMSERVER",
  [string]$SiteCode    = "P01",
  [string]$OutputFile  = ".\cm_bios_export.json"
)

$conn = New-Object System.Data.SqlClient.SqlConnection
$conn.ConnectionString = "Server=$SiteServer;Database=CM_$SiteCode;Integrated Security=SSPI;Connect Timeout=30"
$conn.Open()

$chkCmd = $conn.CreateCommand()
$chkCmd.CommandText = "SELECT COUNT(*) FROM sys.views WHERE name = 'v_GS_COMPUTER_SYSTEM_PRODUCT'"
$hasCsp = [int]$chkCmd.ExecuteScalar() -gt 0

$cspSelect = if ($hasCsp) { ",`n  csp.Version0 AS CSPVersion" } else { ",`n  NULL AS CSPVersion" }
$cspJoin   = if ($hasCsp) { "`nLEFT JOIN v_GS_COMPUTER_SYSTEM_PRODUCT csp ON sys.ResourceID = csp.ResourceID" } else { "" }

$query = @"
SELECT DISTINCT
  sys.Name0               AS ComputerName,
  cs.Manufacturer0        AS Manufacturer,
  cs.Model0               AS Model,
  bios.SMBIOSBIOSVersion0 AS BIOSVersion,
  bios.ReleaseDate0       AS BIOSReleaseDate,
  hw.LastHWScan           AS LastHardwareScan$cspSelect
FROM v_R_System sys
JOIN v_GS_COMPUTER_SYSTEM    cs   ON sys.ResourceID = cs.ResourceID
JOIN v_GS_PC_BIOS            bios ON sys.ResourceID = bios.ResourceID
LEFT JOIN v_GS_WORKSTATION_STATUS hw ON sys.ResourceID = hw.ResourceID$cspJoin
WHERE sys.Client0 = 1
  AND sys.Operating_System_Name_and0 LIKE '%Windows%'
ORDER BY sys.Name0
"@

$cmd = $conn.CreateCommand(); $cmd.CommandText = $query; $cmd.CommandTimeout = 120
$reader = $cmd.ExecuteReader(); $results = @()
while ($reader.Read()) {
  $results += [PSCustomObject]@{
    ComputerName     = $reader["ComputerName"]
    Manufacturer     = $reader["Manufacturer"]
    Model            = $reader["Model"]
    BIOSVersion      = $reader["BIOSVersion"]
    BIOSReleaseDate  = if ($reader["BIOSReleaseDate"] -is [DBNull]) { $null } else { $reader["BIOSReleaseDate"].ToString("yyyy-MM-dd") }
    LastHardwareScan = if ($reader["LastHardwareScan"] -is [DBNull]) { $null } else { $reader["LastHardwareScan"].ToString("yyyy-MM-dd HH:mm") }
    CSPVersion       = if ($reader["CSPVersion"] -is [DBNull]) { $null } else { $reader["CSPVersion"] }
  }
}
$reader.Close(); $conn.Close()
$results | ConvertTo-Json -Depth 3 | Out-File $OutputFile -Encoding UTF8
Write-Host "Exported $($results.Count) devices to $OutputFile" -ForegroundColor Green
```

**Parameters:**

| Parameter | Default | Description |
|---|---|---|
| `-SiteServer` | `CMSERVER` | SQL Server hostname or IP. |
| `-SiteCode` | `P01` | Three-letter site code. Database name: `CM_<SiteCode>`. |
| `-OutputFile` | `.\cm_bios_export.json` | Output JSON file path. |

### CSP Version — HP SBKPFV3 Readiness (optional)

For HP devices, the SMBIOS Type 1 Version field (`Win32_ComputerSystemProduct.Version`) contains the string **SBKPFV3** when the BIOS already supports the new Secure Boot certificates — meaning no BIOS update is needed before the certificate rollout.

The PowerShell script auto-detects whether `v_GS_COMPUTER_SYSTEM_PRODUCT` is enabled and includes it if present.

**Enable the inventory class:** CM Console → *Administration → Client Settings → Hardware Inventory → Set Classes → Add → Win32_ComputerSystemProduct*.

**Verify manually on any HP device:**
```powershell
(Get-CimInstance -ClassName Win32_ComputerSystemProduct).Version
# Ready:     "HP ... SBKPFV3 ..."
# Not ready: "HP EliteDesk 800 G6"  (no SBKPFV3 substring)
```

Source: [HP ISH_13070353](https://support.hp.com/my-en/document/ish_13070353-13070429-16)

### Option B — SSRS Export

```sql
-- SSRS Report Dataset Query (v1.10)
-- Remove the CSPVersion line and JOIN if Win32_ComputerSystemProduct is not enabled.
SELECT DISTINCT
  sys.Name0                                    AS ComputerName,
  cs.Manufacturer0                             AS Manufacturer,
  cs.Model0                                    AS Model,
  bios.SMBIOSBIOSVersion0                      AS BIOSVersion,
  CONVERT(varchar(10), bios.ReleaseDate0, 120) AS BIOSReleaseDate,
  CONVERT(varchar(16), hw.LastHWScan, 120)     AS LastHardwareScan,
  ISNULL(csp.Version0, '''')                AS CSPVersion
FROM v_R_System sys
  JOIN v_GS_COMPUTER_SYSTEM    cs   ON sys.ResourceID = cs.ResourceID
  JOIN v_GS_PC_BIOS            bios ON sys.ResourceID = bios.ResourceID
  LEFT JOIN v_GS_WORKSTATION_STATUS          hw  ON sys.ResourceID = hw.ResourceID
  LEFT JOIN v_GS_COMPUTER_SYSTEM_PRODUCT     csp ON sys.ResourceID = csp.ResourceID
WHERE sys.Client0 = 1
  AND sys.Operating_System_Name_and0 LIKE '%Windows%'
ORDER BY sys.Name0
```

Export via SSRS: *Actions → Export → CSV (comma delimited)*.

---

## 4. Step 2 — Load & Analyse

### JSON Import (PowerShell export)

1. Open `sccm-bios-compliance.html` in your browser.
2. In the **Step 2** card, drop the `.json` file onto the drop zone or click to browse.
3. Click **Run Analysis**.

### CSV Import (SSRS export)

1. Drop or select the `.csv` file in the Step 2 drop zone.
2. The tool auto-detects columns by scanning headers for keywords. Adjust if needed.
3. Click **Run Analysis**.

**CSV column auto-detection keywords:**

| Field | Keywords | Required |
|---|---|---|
| Computer Name | `name`, `computername`, `device`, `hostname` | ✅ Yes |
| Manufacturer | `manufacturer`, `vendor`, `make`, `mfg` | ✅ Yes |
| Model | `model` | ✅ Yes |
| BIOS Version | `bios`, `smbios`, `biosversion`, `firmware` | ✅ Yes |
| BIOS Release Date | `biosdate`, `releasedate`, `date` | No |
| Last HW Scan | `lasthardwarescan`, `lasthwscan`, `hwscan` | No |
| CSP Version | `cspversion`, `cspver`, `computerproduct`, `type1` | No |

---

## 5. Step 3 — Secure Boot Import (optional)

Export the Secure Boot 2023 compliance report from ConfigMgr as **CSV (comma delimited)** and load it here. Expected columns:

| Column | Example values |
|---|---|
| `Computer_Name` | `DESKTOP-001` |
| `Secure_Boot_2023_Status` | `Updated (Compliant)` · `Not Updated (Non-Compliant)` |

**Steps:**
1. Drop the CSV onto the Step 3 drop zone.
2. Auto-detection finds `Computer_Name` and `Secure_Boot_2023_Status`. Adjust if needed.
3. Click **Apply**. Devices are matched by name (case-insensitive).

After applying: Secure Boot column in results table, Secure Boot dropdown filter, two new tiles (OK / Non-Compliant). Devices absent from the report show *Not in report*. Use **Clear** to remove without resetting the main analysis.

---

## 6. Results & Filters

### Summary tiles

| Tile | Description |
|---|---|
| **Total Devices** | Physical devices processed (VMs excluded before counting). |
| **BIOS Up to Date** | Installed BIOS ≥ minimum. Shows count and percentage. |
| **Update Required** | Installed BIOS < minimum. |
| **Not Checked** | No DB entry or no BIOS version from ConfigMgr. |
| **VMs Excluded** *(conditional)* | Shown when at least one VM was detected and excluded. |
| **Secure Boot OK** *(optional)* | After loading Step 3. Compliant count. |
| **Secure Boot Non-Compliant** *(optional)* | After loading Step 3. Non-compliant count. |
| **SBKPFV3 Ready** *(optional)* | HP devices with SBKPFV3 in BIOS (CSP data present). |
| **SBKPFV3 Needed** *(optional)* | HP devices with CSP data but no SBKPFV3 marker. |

### Filter bar

| Filter | Behaviour |
|---|---|
| Search | Case-insensitive substring search across device name and model. |
| Manufacturer | Dropdown from your data; exact manufacturer match. |
| Status | Up to date / Update required / Not checked / End of Life. |
| Min BIOS Date | Hide devices with BIOS date before the selected date. |
| Secure Boot *(optional)* | Visible after loading Step 3 report. |
| SBKPFV3 (HP) *(optional)* | Ready / Update needed / No data. Visible when CSP data present. |

### Table columns

All columns sortable by clicking the header. Default: *Update Required* first.

| Column | Source | Notes |
|---|---|---|
| Device Name | ConfigMgr | `Name0` from `v_R_System`. |
| Manufacturer | ConfigMgr | Raw string from `v_GS_COMPUTER_SYSTEM`. |
| Model | ConfigMgr | From `v_GS_COMPUTER_SYSTEM`. Used for DB lookup. |
| BIOS (installed) | ConfigMgr | Normalised from `SMBIOSBIOSVersion0`. HP family codes stripped. |
| BIOS (minimum) | BIOS DB | Vendor-published minimum for Secure Boot 2023. |
| DB Model (matched) | BIOS DB | Exact DB entry used. Lenovo MT lookups show `model (MT:XXXX)`. |
| Status | Computed | See [Status Codes](#10-status-codes). |
| BIOS Date | ConfigMgr | From `v_GS_PC_BIOS`. |
| Last HW Scan | ConfigMgr | From `v_GS_WORKSTATION_STATUS`. |
| Secure Boot *(optional)* | Step 3 CSV | Compliant / Non-Compliant / Not in report. |
| SBKPFV3 *(optional)* | CSPVersion field | HP only: SBKPFV3 Ready / Update Needed / No Data. Non-HP shows —. |

---

## 7. Export

The **Export ▾** dropdown offers three formats. All respect current filters.

### CSV

UTF-8 with BOM. Opens correctly in Excel without import dialogs.

| Column | Content |
|---|---|
| Computer Name – Last HW Scan | Standard device fields |
| Secure Boot *(optional)* | Included when Step 3 data loaded |
| CSP Version *(optional)* | Raw SMBIOS Type 1 string |
| SBKPFV3 Status *(optional)* | `SBKPFV3 Ready`, `Update Needed`, `No Data`, or `N/A` |
| Status | `Up to date`, `Update required`, `Not checked`, or `End of Life` |

### HTML Report

Self-contained `.html` file with stat card snapshot and interactive sortable table. Click any column header to sort (▲/▼). Prints cleanly from the browser.

> Text columns use locale-aware numeric sorting so `1.9.0` sorts before `1.10.0`. Status/Secure Boot columns sort by logical compliance order.

### PDF / Print

Browser native print dialog with dedicated print stylesheet: import card hidden, timestamp header added, table headers repeat per page. Choose **Save as PDF**.

---

## 8. BIOS Database

| Vendor | Entries | Source |
|---|---|---|
| Dell | 218 | KB000347876 · 2026 |
| HP | 319 | ISH_13070353 · 2025/2026 |
| Lenovo | 651 | HT518129 · incl. MT codes |

Additionally, the `LENOVO_MT` table maps ~250 4-char machine type codes to their BIOS DB keys.

> **⚠️ Database currency:** Vendors update requirements continuously. Verify critical decisions directly against the vendor KB articles.

### Model Matching

A four-stage pipeline resolves ConfigMgr model strings to database entries:

**Stage 1 — Exact match (case-insensitive)**
Both strings normalised (lowercase, punctuation → spaces) and compared directly.

**Stage 2 — Substring containment, longest wins**
If the device model contains the DB entry as a substring or vice versa, the longest match is used. Handles suffixes like "Notebook PC".

**Stage 3 — Jaccard word-set similarity ≥ 60%**
Intersection-over-union of word sets ≥ 0.60 → best-scoring entry used. Catches minor naming variations.

**Stage 4 — Lenovo machine type code fallback (Lenovo only)**
If Stages 1–3 all fail for a Lenovo device, the first 4 characters of the model string are extracted as a machine type code and looked up in `LENOVO_MT`.

The **DB Model (matched)** column shows exactly which entry was used.

### Lenovo Machine Type Code Lookup

ConfigMgr normally reports Lenovo product names via `Win32_ComputerSystem.Model` (e.g. *ThinkPad T14 Gen 1*). However, some devices report only their 4-char machine type code (e.g. *20S1*) — typically those where the BIOS has never been updated since leaving the factory.

The `LENOVO_MT` table maps ~250 such codes to BIOS DB keys. When a Stage 4 match is found, the DB Model column shows `model name (MT:XXXX)`.

**BIOS-family disambiguation:** Some machine types shipped with multiple BIOS platforms that have different minimum versions. The `LENOVO_MT_BIOS` table uses the first 5 characters of the raw BIOSVersion string as an additional key:

```
// Example: MT "20VX" with BIOS "N3WET..." → composite key "20VX_N3WET" → min 1.13
// Example: MT "20VX" with BIOS "N34ET..." → no composite match  → min 1.61
```

**Disambiguation variants in the BIOS DB:**

| DB key | Min | Platform note |
|---|---|---|
| `p14s gen 2 n3w` | 1.13 | N3WET (lower than standard N34ET 1.61) |
| `p15s gen 2 n3w` | 1.13 | N3WET platform |
| `p16v gen 1 n3u` | 1.30 | N3UET (lower than standard N3VET 1.50) |
| `x1 carbon gen 7 n2h` | 1.60 | N2HET (higher than standard N2QET 1.49) |
| `x1 yoga gen 4 n2h` | 1.60 | N2HET platform |
| `x390 n2j` | 1.86 | N2JET (much higher than standard N2SET 1.31) |
| `t490 cml` | 1.24 | CML platform (higher than standard T490 1.82) |
| `l13/l14/l15 gen 4 r24` | 1.21 | R24ET (higher than standard R25ET 1.16) |
| `l13/l13 yoga gen 4 r27` | 1.17 | R27ET (higher than standard R26ET 1.15) |

### BIOS Version Normalization

| Raw value | Normalized | Pattern |
|---|---|---|
| `T93 Ver. 01.23.00` | `01.23.00` | HP family code prefix |
| `J01 v02.33` | `02.33` | HP family code + v |
| `ver. 1.19.0` | `1.19.0` | Leading "ver." |
| `Version 1.82` | `1.82` | Leading "Version" |
| `1.72 (ThinkPad)` | `1.72` | Lenovo parenthetical suffix |
| `A19` | `A19` | Dell alpha — passed through |
| `F.22` | `0.22` | HP legacy F.xx format |

### Version Comparison

Strings split on `.` and `-`, each segment compared numerically. `1.9.0` correctly ranks below `1.10.0`. Non-numeric segments use locale-aware comparison with `numeric: true`. If either version is unknown → *Not Checked*.

---

## 9. VM Exclusion

Virtual machines are automatically excluded before analysis. They cannot receive BIOS updates through standard vendor channels and would generate false positives. Excluded devices do not appear in results, counts, or exports.

When VMs are detected, a **VMs Excluded** tile shows the count with sub-label "not analysed".

**Detection signals (case-insensitive):**

| Field | Value | Platform |
|---|---|---|
| Model | contains `virtual machine` | Microsoft Hyper-V, VirtualBox |
| BIOSVersion | contains `hyper-v` | Microsoft Hyper-V BIOS string |
| Manufacturer | contains `vmware` | VMware (e.g. "VMware, Inc.") |
| Model | contains `vmware` | VMware (e.g. "VMware7,1") |

---

## 10. Status Codes

| Status | Meaning | Action |
|---|---|---|
| ✅ Up to date | Installed BIOS ≥ minimum. Device meets the prerequisite. | None required. |
| ❌ Update required | Installed BIOS < minimum. Applying the Secure Boot update before updating the BIOS may cause boot failure. | Update BIOS to at least the version in *BIOS (minimum)* before the WU installs. |
| ⬜ Not checked | No DB entry for this model, or no BIOS version from ConfigMgr. | Verify Hardware Inventory. Check if model should be in the database. |
| 🟡 End of Life | Vendor has published no BIOS update for this model. Device cannot be made compliant. | Consider hardware replacement. Do not allow the Secure Boot update until a vendor fix is available, or accept and test thoroughly. |

> **⚠️ Before deploying the Secure Boot 2023 update:** Ensure all *Update Required* devices have their BIOS updated first. Validate with a second tool run before allowing the Windows Update to proceed.

---

## 11. Changelog

### v1.10 — June 2026
**Lenovo machine type code lookup + EOL status**
- Added `LENOVO_MT` table mapping ~250 4-char Lenovo MT codes to BIOS DB keys — Stage 4 fallback when name matching fails
- Added `LENOVO_MT_BIOS` table for BIOS-family disambiguation (same MT code, different platform → different minimum)
- DB Model column shows `model name (MT:XXXX)` for MT-code-resolved matches
- Added 21 Lenovo disambiguation entries; Lenovo DB now at 651 entries, matching Intune tool
- *End of Life* DB entries now surface as distinct **End of Life** status instead of *Not Checked*
- EOL added to status filter and all export formats

### v1.9.x — June 2026
**VMware VM exclusion**
- Extended VM detection to VMware: `Manufacturer` contains "vmware" (catches "VMware, Inc."), `Model` contains "vmware" (catches "VMware7,1")
- Previous version only detected Hyper-V and generic "virtual machine" model strings

### v1.9 — May 2026
**SBKPFV3 HP readiness check + VM exclusion**
- New optional SBKPFV3 check for HP devices via `Win32_ComputerSystemProduct.Version` (CSP Version)
- PowerShell script auto-detects `v_GS_COMPUTER_SYSTEM_PRODUCT` and conditionally includes CSP Version
- Two new stat tiles (SBKPFV3 Ready / Needed), filter dropdown, sortable table column
- SBKPFV3 data in CSV and HTML report exports
- VM auto-exclusion: "virtual machine" model or "hyper-v" BIOS → excluded before analysis
- VMs Excluded stat tile

### v1.8.1 — May 2026
**Bug fix — Secure Boot CSV column indexing**
- Fixed: all devices shown as *Not in report* after loading Secure Boot CSV
- Root cause: integer index used as string key for row field access
- Fix: corrected to use integer indices directly

### v1.8 — May 2026
**Export dropdown — HTML report and PDF**
- Export ▾ dropdown: CSV, HTML report, PDF / Print
- HTML report: interactive sortable table with `localeCompare` numeric sorting
- PDF: print stylesheet, timestamp header, repeating table headers

### v1.7 — May 2026
**Import layout — vertical pipeline**
- Three import steps in one card with vertical left-side timeline
- Step 3 visually optional: muted heading, dashed dot, optional badge

### v1.6 — May 2026
**Step 3 — Secure Boot cross-reference**
- Load ConfigMgr Secure Boot 2023 CSV; Secure Boot column, tiles, filter, export column

### v1.4 — May 2026
**Layout improvements** — Full screen width, auto-sizing columns, responsive filter bar

### v1.3 — May 2026
**HP database refresh** — 111 → 304 models (HP ISH_13070353)

### v1.2 — May 2026
**Visual refresh** — IBM Plex Mono + Sans, blue accent, redesigned stat tiles

### v1.1 — May 2026
**HP normalization fix** — HP family-code pattern detected first

### v1.0 — May 2026
**Initial release** — PowerShell script, SSRS query, JSON/CSV import, compliance engine
