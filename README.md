# ConfigMgr BIOS Compliance Checker

**Version:** 1.4 · **Platform:** Microsoft Endpoint Configuration Manager (MECM / SCCM)  
**Purpose:** Secure Boot 2023 · UEFI Certificate Prerequisites

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Requirements](#2-requirements)
3. [Step 1 — Export Device Data](#3-step-1--export-device-data)
   - [Option A — PowerShell Export (recommended)](#option-a--powershell-export-recommended)
   - [Option B — SSRS Export](#option-b--ssrs-export)
4. [Step 2 — Load & Analyse](#4-step-2--load--analyse)
   - [JSON Import](#json-import-powershell-export)
   - [CSV Import](#csv-import-ssrs-export)
5. [Results & Filters](#5-results--filters)
6. [CSV Export](#6-csv-export)
7. [BIOS Database](#7-bios-database)
   - [Model Matching](#model-matching)
   - [Version Normalization](#bios-version-normalization)
   - [Version Comparison](#version-comparison)
8. [Status Codes](#8-status-codes)
9. [Changelog](#9-changelog)

---

## 1. Introduction

The ConfigMgr BIOS Compliance Checker is a self-contained HTML tool that identifies devices in your ConfigMgr environment whose BIOS version does not meet the minimum requirement for the **Secure Boot 2023 UEFI certificate update**.

Devices that receive the Windows Update carrying the new Secure Boot certificate without a sufficiently recent BIOS may fail to boot. Vendors published minimum BIOS version requirements; this tool checks your entire ConfigMgr device inventory against those requirements in seconds — no server-side component, no agent, no network connection needed at runtime.

### How it works

1. Export hardware inventory data (BIOS version, model, manufacturer) from ConfigMgr using the provided PowerShell script or an SSRS report.
2. Load the exported `.json` or `.csv` file into the tool.
3. The tool matches each device's model against the built-in BIOS database and compares the installed version against the vendor minimum.
4. Results are shown in a filterable, sortable table with summary tiles. Non-compliant devices are sorted to the top by default.

### Compared to the Intune tool

The core compliance engine — BIOS database, model matching logic, and version comparison — is identical to the Intune BIOS Compliance Checker. The differences are in how data is sourced:

| Feature | ConfigMgr Tool | Intune Tool |
|---|---|---|
| Data source | PowerShell / SSRS export | Graph API / CSV export |
| Auth required at runtime | No — file-based | Yes (Graph) / No (CSV) |
| Secure Boot column | Not included | Optional (CSV import) |
| Last HW Scan column | ✓ Included | Not available |
| BIOS database | Identical | Identical |
| Model matching | Identical | Identical |

---

## 2. Requirements

| Component | Requirement |
|---|---|
| Browser | Any modern browser (Chrome, Edge, Firefox, Safari). No extensions required. |
| ConfigMgr permissions (PowerShell export) | Read access to the ConfigMgr site database. The built-in **Read-Only Analyst** role is sufficient. Required views: `v_R_System`, `v_GS_COMPUTER_SYSTEM`, `v_GS_PC_BIOS`, `v_GS_WORKSTATION_STATUS`. |
| ConfigMgr permissions (SSRS export) | Read access to the SSRS report. The ConfigMgr **Report Users** security role is sufficient. |
| Hardware Inventory | Must be enabled and devices must have reported at least once. Without it, `SMBIOSBIOSVersion` and other fields will be empty. |

> **⚠️ Hardware Inventory data quality**  
> Devices that have not reported Hardware Inventory recently will appear with an empty BIOS version and will be classified as *Not Checked*. Check the **Last HW Scan** column — dates older than 30 days may indicate stale data.

---

## 3. Step 1 — Export Device Data

The tool accepts two file formats: **JSON** (from the PowerShell export script) and **CSV** (from SSRS or any tabular export). Both contain the same fields.

### Option A — PowerShell Export (recommended)

Run the following script on any machine with network access to the ConfigMgr site database server. It queries the hardware inventory views directly and writes a JSON file.

```powershell
# ConfigMgr BIOS Export Script
# Run on SMS Provider or any machine with SQL read access to the CM DB
# Requires: Read-Only Analyst role or equivalent SQL read permissions

param(
  [string]$SiteServer  = "CMSERVER",      # SQL server hostname
  [string]$SiteCode    = "P01",           # Your 3-letter site code
  [string]$OutputFile  = ".\cm_bios_export.json"
)

$query = @"
SELECT DISTINCT
  sys.Name0                          AS ComputerName,
  cs.Manufacturer0                   AS Manufacturer,
  cs.Model0                          AS Model,
  bios.SMBIOSBIOSVersion0            AS BIOSVersion,
  bios.ReleaseDate0                  AS BIOSReleaseDate,
  hw.LastHWScan                      AS LastHardwareScan
FROM v_R_System sys
JOIN v_GS_COMPUTER_SYSTEM    cs   ON sys.ResourceID = cs.ResourceID
JOIN v_GS_PC_BIOS            bios ON sys.ResourceID = bios.ResourceID
LEFT JOIN v_GS_WORKSTATION_STATUS hw ON sys.ResourceID = hw.ResourceID
WHERE sys.Client0 = 1
  AND sys.Operating_System_Name_and0 LIKE '%Windows%'
ORDER BY sys.Name0
"@

$conn = New-Object System.Data.SqlClient.SqlConnection
$conn.ConnectionString = "Server=$SiteServer;Database=CM_$SiteCode;" +
                         "Integrated Security=SSPI;Connect Timeout=30"
$conn.Open()
$cmd = $conn.CreateCommand()
$cmd.CommandText = $query
$cmd.CommandTimeout = 120
$reader = $cmd.ExecuteReader()
$results = @()
while ($reader.Read()) {
  $results += [PSCustomObject]@{
    ComputerName     = $reader["ComputerName"]
    Manufacturer     = $reader["Manufacturer"]
    Model            = $reader["Model"]
    BIOSVersion      = $reader["BIOSVersion"]
    BIOSReleaseDate  = if ($reader["BIOSReleaseDate"] -is [DBNull]) { $null }
                       else { $reader["BIOSReleaseDate"].ToString("yyyy-MM-dd") }
    LastHardwareScan = if ($reader["LastHardwareScan"] -is [DBNull]) { $null }
                       else { $reader["LastHardwareScan"].ToString("yyyy-MM-dd HH:mm") }
  }
}
$reader.Close(); $conn.Close()
$results | ConvertTo-Json -Depth 3 | Out-File $OutputFile -Encoding UTF8
Write-Host "Exported $($results.Count) devices to $OutputFile" -ForegroundColor Green
```

#### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-SiteServer` | `CMSERVER` | Hostname or IP of the SQL Server hosting the ConfigMgr database. |
| `-SiteCode` | `P01` | Your ConfigMgr three-letter site code. The database name is derived as `CM_<SiteCode>`. |
| `-OutputFile` | `.\cm_bios_export.json` | Path and filename for the output JSON file. |

> **ℹ️ Running on the site server**  
> If you run the script on the ConfigMgr site server itself, `SiteServer` can usually be `localhost` or the local machine name. Integrated Security (Windows Authentication) is used — no SQL credentials needed.

---

### Option B — SSRS Export

Create a custom report in the ConfigMgr Reporting Services portal using the SQL query below, then export the results as CSV directly from the SSRS report viewer.

```sql
-- SSRS Report Dataset Query
-- Add as an embedded or shared dataset in your report
SELECT DISTINCT
  sys.Name0                                    AS ComputerName,
  cs.Manufacturer0                             AS Manufacturer,
  cs.Model0                                    AS Model,
  bios.SMBIOSBIOSVersion0                      AS BIOSVersion,
  CONVERT(varchar(10), bios.ReleaseDate0, 120) AS BIOSReleaseDate,
  CONVERT(varchar(16), hw.LastHWScan, 120)     AS LastHardwareScan
FROM v_R_System sys
  JOIN v_GS_COMPUTER_SYSTEM    cs   ON sys.ResourceID = cs.ResourceID
  JOIN v_GS_PC_BIOS            bios ON sys.ResourceID = bios.ResourceID
  LEFT JOIN v_GS_WORKSTATION_STATUS hw ON sys.ResourceID = hw.ResourceID
WHERE sys.Client0 = 1
  AND sys.Operating_System_Name_and0 LIKE '%Windows%'
ORDER BY sys.Name0
```

In the SSRS report viewer, click **Actions → Export → CSV (comma delimited)** to download the file, then load it in Step 2.

> **⚠️ SSRS JSON export is not supported**  
> SSRS Data Feed exports are in ATOM format, not JSON. Use *CSV (comma delimited)* and load the file using the CSV import path in the tool.

---

## 4. Step 2 — Load & Analyse

### JSON Import (PowerShell export)

1. Open `sccm-bios-compliance.html` in your browser.
2. In the **Step 2** card, click the drop zone or drag the `.json` file onto it.
3. The tool shows the filename and record count in the drop zone.
4. Click **Run Analysis**.

### CSV Import (SSRS export)

1. Open `sccm-bios-compliance.html` in your browser.
2. Drop or select the `.csv` file in the Step 2 drop zone.
3. The tool auto-detects columns by scanning headers for keywords. Adjust the column selectors if the auto-mapping is incorrect.
4. Click **Run Analysis**.

#### CSV column auto-detection keywords

| Field | Keywords searched in header | Required |
|---|---|---|
| Computer Name | `name`, `computername`, `device`, `hostname` | ✅ Yes |
| Manufacturer | `manufacturer`, `vendor`, `make`, `mfg` | ✅ Yes |
| Model | `model` | ✅ Yes |
| BIOS Version | `bios`, `smbios`, `biosversion`, `firmware` | ✅ Yes |
| BIOS Release Date | `biosdate`, `releasedate`, `date` | No |
| Last HW Scan | `lasthardwarescan`, `lasthwscan`, `hwscan` | No |

> **ℹ️** The CSV parser is fully RFC 4180-compliant and handles quoted fields, embedded commas, and multi-line values. Both UTF-8 and UTF-8 with BOM are accepted.

---

## 5. Results & Filters

### Summary tiles

After analysis, four tiles appear at the top of the page:

| Tile | Description |
|---|---|
| **Total Devices** | Total number of device records processed from the import. |
| **BIOS Up to Date** | Devices whose installed BIOS version is ≥ the minimum required version. Shows count and percentage. |
| **Update Required** | Devices whose installed BIOS version is < the minimum required version. |
| **Not Checked** | Devices with no matching entry in the BIOS database, or no BIOS version reported by ConfigMgr. |

### Filter bar

| Filter | Behaviour |
|---|---|
| Search | Case-insensitive substring search across device name and model. |
| Manufacturer | Dropdown populated from the actual manufacturers in your data. Filters to exact manufacturer match. |
| Status | Show only *Up to date*, *Update required*, or *Not checked* devices. |
| Min BIOS Date | Hide devices whose BIOS release date is before the selected date. Useful for focusing on recently updated BIOSes. |

### Table columns

All columns are sortable by clicking the header. The default sort shows **Update Required** devices first.

| Column | Source | Notes |
|---|---|---|
| Device Name | ConfigMgr | The `Name0` value from `v_R_System`. |
| Manufacturer | ConfigMgr | Raw manufacturer string from `v_GS_COMPUTER_SYSTEM`. May be `HP` or `Hewlett-Packard` depending on device generation — both are handled by vendor detection. |
| Model | ConfigMgr | Full model name from `v_GS_COMPUTER_SYSTEM`. Used for BIOS DB lookup. |
| BIOS (installed) | ConfigMgr | Normalised BIOS version extracted from `SMBIOSBIOSVersion0`. HP family codes (e.g. `T93 Ver. 01.23.00` → `01.23.00`) are stripped automatically. |
| BIOS (minimum) | BIOS DB | The vendor-published minimum version required for the Secure Boot 2023 certificate update. |
| DB Model (matched) | BIOS DB | The exact database entry used for the lookup. Useful for verifying fuzzy or substring matches. |
| Status | Computed | Compliance result. See [Status Codes](#8-status-codes). |
| BIOS Date | ConfigMgr | Release date of the installed BIOS from `v_GS_PC_BIOS`. |
| Last HW Scan | ConfigMgr | Date of the last Hardware Inventory cycle from `v_GS_WORKSTATION_STATUS`. Stale dates may indicate outdated data. |

---

## 6. CSV Export

The **⬇ Export CSV** button exports the currently filtered view — only the rows visible in the table at the time of export are included.

| Column | Content |
|---|---|
| Computer Name | Device name from ConfigMgr |
| Manufacturer | Manufacturer name from ConfigMgr |
| Model | Model name from ConfigMgr |
| BIOS (installed) | Normalised BIOS version (HP family code stripped) |
| BIOS (installed raw) | Original raw value as returned by ConfigMgr |
| BIOS (minimum) | Minimum version from the BIOS database |
| DB Model (matched) | Database entry used for the compliance lookup |
| Status | `Up to date`, `Update required`, or `Not checked` |
| BIOS Release Date | Release date of the installed BIOS |
| Last HW Scan | Last Hardware Inventory date from ConfigMgr |

The file is exported as **UTF-8 with BOM** so it opens correctly in Excel without import dialogs.

---

## 7. BIOS Database

| Vendor | Models | Source |
|---|---|---|
| Dell | ~218 | KB000347876 · Feb 2026 |
| HP | 304 | ISH_13070353 · 2025/2026 |
| Lenovo | ~92 | HT518129 |

The database maps manufacturer + model name to the minimum BIOS version required before the Secure Boot 2023 UEFI certificate update can be safely applied via Windows Update.

> **⚠️ Database currency**  
> Vendors update their requirements continuously. The versions embedded in the tool reflect the source articles at the time of the last database update. For compliance decisions in critical environments, verify directly against the vendor KB articles above.

---

### Model Matching

ConfigMgr model strings often include extra words not present in vendor databases (e.g. *"HP EliteBook x360 1030 G8 Notebook PC"* vs *"HP EliteBook x360 1030 G8"*). The tool uses a three-stage matching pipeline:

**Stage 1 — Exact match (case-insensitive)**  
Both strings are normalised (lowercase, punctuation collapsed to spaces) and compared directly. If equal, the match is used immediately.

↓ *if no match*

**Stage 2 — Substring containment (longest wins)**  
If the device model contains the DB entry as a substring, or vice versa, the longest matching DB entry is used. This handles common suffixes like "Notebook PC" or "Desktop PC".

↓ *if no match*

**Stage 3 — Jaccard word-set similarity ≥ 60%**  
The word sets of both strings are compared. If the intersection-over-union score is at least 0.60, the highest-scoring DB entry is used. This catches minor naming variations like swapped words or abbreviated terms.

The **DB Model (matched)** column in the results table shows exactly which database entry was used, making it easy to verify match quality.

---

### BIOS Version Normalization

ConfigMgr returns raw BIOS version strings from WMI that include vendor-specific prefixes. The tool strips these to extract a comparable numeric version:

| Raw value (from ConfigMgr) | Normalised | Pattern |
|---|---|---|
| `T93 Ver. 01.23.00` | `01.23.00` | HP family code prefix |
| `Q78 Ver. 01.31.00` | `01.31.00` | HP family code prefix |
| `J01 v02.33` | `02.33` | HP family code + lowercase v |
| `ver. 1.19.0` | `1.19.0` | Leading "ver." prefix |
| `Version 1.82` | `1.82` | Leading "Version" prefix |
| `1.72 (ThinkPad)` | `1.72` | Lenovo parenthetical suffix |
| `A19` | `A19` | Dell alpha prefix — passed through |
| `F.22` | `0.22` | HP legacy F.xx format |

> **ℹ️** The HP family code format (`XYZ Ver. nn.nn.nn`) is detected by a regex that matches 2–4 uppercase alphanumeric characters followed by a space and `Ver.` or `v` and a digit. This prevents false matches on model-name strings that begin with letters.

---

### Version Comparison

Version strings are split on `.` and `-` delimiters and each segment is compared numerically. This ensures `1.9.0` is correctly ranked below `1.10.0` (since 10 > 9 numerically, not lexicographically).

If a segment cannot be parsed as a number (e.g. Dell's `A19`), it falls back to locale-aware string comparison with `numeric: true`, which still handles mixed alphanumeric strings sensibly.

If either the installed or minimum version cannot be determined, the result is *Not Checked* rather than a false positive or false negative.

---

## 8. Status Codes

| Status | Meaning | Action |
|---|---|---|
| ✅ **Up to date** | Installed BIOS version ≥ minimum version in the database. The device meets the prerequisite for the Secure Boot 2023 certificate update. | None required. |
| 🔴 **Update required** | Installed BIOS version < minimum version. Applying the Secure Boot certificate update before updating the BIOS may cause boot failure. | Update BIOS to at least the version shown in the *BIOS (minimum)* column before allowing the Secure Boot WU to install. |
| ⚪ **Not checked** | No entry in the BIOS database for this vendor/model, *or* ConfigMgr did not return a BIOS version for this device. | Check whether the model should be in the database. If the BIOS version is missing, verify that Hardware Inventory has run successfully on the device. |

> **🔴 Before deploying the Secure Boot 2023 update**  
> Ensure all devices showing *Update Required* have their BIOS updated first. Use a ConfigMgr Task Sequence or vendor-specific BIOS update package. Validate with a second run of this tool before allowing the Windows Update to proceed.

---

## 9. Changelog

### v1.4 — May 2026
**Layout & formatting improvements**
- Removed fixed max-width on main container — layout now fills available screen width
- Table columns auto-size to content; no more horizontal page scrollbar
- Model and DB Model columns now wrap instead of forcing table overflow
- Removed inline max-width clipping on DB Model cell
- Responsive filter bar stacks cleanly on narrow viewports

### v1.3 — May 2026
**Complete HP database refresh**
- HP database expanded from 111 to 304 models (source: HP ISH_13070353)
- Old short-key entries replaced with full product names matching ConfigMgr WMI output
- Added EliteDesk G5/G8, EliteOne G9, ProDesk G7/G8, ZBook G9/G10, Dragonfly series, workstations (Z2/Z4/Z6/Z8), thin clients, retail systems, conference PCs
- End of Life entry (HP 470 G9) correctly excluded

### v1.2 — May 2026
**Visual refresh — IBM Plex design system**
- Fonts changed from JetBrains Mono + Syne to IBM Plex Mono + IBM Plex Sans
- Accent colour changed from orange (`#f78166`) to blue (`#58a6ff`) to match the Intune tool
- Stat tiles redesigned with top accent bar; badges changed to square-cornered style
- Status bar backgrounds tinted to match state colour

### v1.1 — May 2026
**HP BIOS version normalization fix**
- Fixed: HP BIOS strings in format `T93 Ver. 01.23.00` were truncated to the 3-char family code (`T93`) in both the display and the comparison
- Root cause: the Lenovo trailing-junk stripper (`/\s+.*$/`) fired before vendor-prefix removal, cutting everything after the first space
- Fix: HP family-code pattern (`/^[A-Z0-9]{2,4}\s+(?:Ver\.\s*|v)(\d[\d.]+)/i`) is now detected and extracted first
- Also fixed: older HP format `J01 v02.33` now normalises correctly to `02.33`

### v1.0 — May 2026
**Initial release**
- PowerShell export script and SSRS dataset query
- JSON and CSV file import with auto column mapping
- BIOS compliance engine: same DB, normalization, and matching logic as the Intune tool
- Summary tiles, filter bar, sortable table, CSV export
- Last HW Scan column for data quality visibility
