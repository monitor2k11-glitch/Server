# SysAnalyzer — Advanced PowerShell System Analysis Toolkit

Reusable PowerShell functions for gathering **CPU, Memory, Storage, installed
applications (with versions) and installed patches** from **one computer or a
group of computers**, and generating a **fully self-contained HTML report**
with embedded CSS and JavaScript — no CDN, fonts, images or network requests
of any kind. The report works offline in any modern browser.

```
SysAnalyzer/
├── SysAnalyzer.psm1              # Module: collectors + orchestrator + report/CSV exporters
├── SysAnalyzer.psd1             # Module manifest
├── Assets/ReportTemplate.html    # Self-contained HTML/CSS/JS report template
├── Run-SystemAnalysis.ps1        # One-shot runner script
├── Tests/Run-Tests.ps1           # Presentation/export test suite (runs on any OS)
├── Tests/Run-MockedTests.ps1      # Mocked collector/orchestrator/runner tests
├── Tests/Generate-DemoReport.ps1  # Demo report from synthetic data
├── Tests/js-smoke-test.js        # Runtime test of the report JavaScript (Node)
└── README.md
```

## Requirements

- **Windows PowerShell 5.1** or **PowerShell 7+** on Windows.
- Local collection: works out of the box (some classes need admin rights).
- Remote collection: WMI/CIM access (WinRM **or** DCOM/RPC reachable).
  The module never enables or weakens remoting and never installs anything
  on remote hosts.
- HTML report: any modern browser. Nothing else.

## Quick start

```powershell
# Analyse the local computer and open a report
.\Run-SystemAnalysis.ps1

# Analyse a group of computers (parallel on PowerShell 7+, default throttle 8)
.\Run-SystemAnalysis.ps1 -ComputerName WEBSRV01, DBSRV02, APPSRV03 -Credential (Get-Credential)

# Analyse a fleet from a file, richer local collection, custom output
.\Run-SystemAnalysis.ps1 -ComputerName (Get-Content .\servers.txt) `
    -OutputPath .\Fleet.html -Title 'Monthly Fleet Audit' -ThrottleLimit 16
```

The runner produces:

- `SystemAnalysisReport.html` — the self-contained report
- `Csv/<HOST>_Applications.csv`, `Csv/<HOST>_Patches.csv`, `Csv/<HOST>_Summary.csv`

## Module functions

### Collectors (each usable standalone, locally or remotely)

| Function | What it returns |
|---|---|
| `Get-SystemSummary` | Identity, domain, manufacturer/model/serial, BIOS, OS name/version/build/architecture, install date, last boot, uptime, time zone |
| `Get-SystemCPU` | Physical processors (name, clocks, caches, sockets), total cores/logical CPUs, current utilization % |
| `Get-SystemMemory` | Total/available/used memory, DIMM inventory (capacity, speed, part number, slot), page file usage |
| `Get-SystemStorage` | Every fixed volume (size, free, file system, usage %), physical disks (model, interface, size, partitions), totals |
| `Get-InstalledApplications` | All registered applications with versions: machine 64-bit + 32-bit (WOW6432Node) + per-user (HKU) + optional Appx/Store packages |
| `Get-SystemPatches` | Installed hotfixes/updates from the QFE list (the installed-patch inventory) |
| `Get-WindowsUpdateHistory` | Local Windows Update installation-event history (clearly labelled as history, not installed state) |

Every collector accepts `-ComputerName` (creates a temporary CIM session),
`-CimSession` (reuse your own session), and `-OperationTimeoutSec`.
Exception: `Get-WindowsUpdateHistory` takes no parameters and runs on the
local host only (the Windows Update Agent COM API is not remotely
accessible).

```powershell
Get-SystemCPU -ComputerName WEBSRV01
Get-InstalledApplications -ComputerName WEBSRV01 | Sort-Object Name | Export-Csv apps.csv
Get-SystemPatches -ComputerName WEBSRV01 | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-30) }

# Reuse one session for many categories
$s = New-CimSession -ComputerName WEBSRV01 -Credential (Get-Credential)
Get-SystemSummary -CimSession $s
Get-SystemStorage -CimSession $s
Remove-CimSession $s
```

### Orchestrator

`Invoke-SystemAnalysis` runs every collector against one or many computers
and returns one consistent object per host:

```powershell
$results = Invoke-SystemAnalysis -ComputerName WEBSRV01, DBSRV02 -IncludeAppx -IncludeWindowsUpdates
$results[0].Applications.Count
$results[0].Coverage
$results[1].CollectionErrors
```

Robustness features:

- **One CIM session per host** used for every category (WinRM with automatic
  DCOM fallback), disposed reliably.
- **Per-category error handling** — a failing category never aborts the host;
  successful categories are preserved and failures recorded in
  `CollectionErrors`.
- **Coverage tracking** per category (`Complete` / `Partial` / `Failed`) with
  human-readable `CoverageNotes` explaining scope limits. An empty inventory
  is never silently treated as an error.
- **Bounded parallel fan-out** on PowerShell 7+ (`-ThrottleLimit`, default 8);
  automatic sequential fallback on Windows PowerShell 5.1 or with `-Sequential`.
- Unreachable hosts return `Status = 'Unreachable'` with the connection error —
  never an exception.

### Presentation

```powershell
# Self-contained HTML report
New-SystemHTMLReport -AnalysisResult $results -Path .\Report.html -Title 'Fleet Audit'

# CSV exports (per host: applications, patches, summary+coverage+errors)
Export-SystemAnalysisCsv -AnalysisResult $results -OutputDirectory .\Csv
```

## The HTML report

Everything — CSS, JavaScript and data — is embedded in a single `.html` file:

- **Fleet overview**: aggregate stats (hosts, apps, patches, RAM, storage),
  per-host cards with status, CPU/RAM bars and quick counts.
- **Host detail**: system identity, OS info, CPU/memory/storage panels with
  capacity meters, DIMM and physical-disk tables.
- **Searchable, sortable** application and patch tables with CSV export of
  the currently visible rows.
- **Coverage & errors panel** per host: per-category status and every
  collection error, always visible.
- Host switcher (dropdown + cards), fully responsive, dark theme.

Security: data is embedded as escaped JSON in a `type="application/json"`
block (`</` sequences escaped so collected strings cannot terminate it) and
rendered exclusively with DOM APIs / `textContent` — collected strings can
never inject HTML or script into the report.

## Design decisions & documented scope limits

- **Applications** are inventoried from the registry (Add/Remove Programs entries,
  the [Uninstall registry key](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key)),
  *not* via `Win32_Product`. Microsoft's own class documentation warns that querying
  `Win32_Product` "initiates a consistency check of packages installed, verifying and
  repairing the install" — i.e. it can trigger MSI self-repair
  ([Win32_Product class](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/msiprov/win32-product)).
  Covered: machine-wide installs (both 64-bit and WOW6432Node registry views) and
  per-user installs of every *loaded* profile hive, plus optional Appx/Store
  packages (local host only; `-AllUsers` is attempted first and falls back to the
  current user). Portable/unregistered software and apps in *unloaded* profiles
  are inherently invisible to this method — coverage is always reported as
  `Partial`, never silently "complete".
- **Patches** come from the Quick Fix Engineering list
  ([Win32_QuickFixEngineering](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering),
  the same data as [Get-HotFix](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix)).
  Microsoft documents that the class "returns only the updates supplied by Component
  Based Servicing (CBS)", so coverage is reported as `Partial`. With
  `-IncludeWindowsUpdates`, the local Windows Update installation history is
  collected as a *separate* `UpdateHistory` category (successful installation
  events only — failed/aborted entries are excluded) and is never merged into
  the patch inventory or its counts: an installed event may later have been
  superseded or removed, so it is history, not current installed state.
- Remote access uses one authenticated CIM session per host (WinRM, DCOM
  fallback). Nothing is installed remotely; remoting is never enabled or
  weakened. Credentials are accepted via `-Credential` and never serialized
  into reports. Parallel fan-out uses
  [ForEach-Object -Parallel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/foreach-object)
  on PowerShell 7+ with a sequential fallback on Windows PowerShell 5.1.

## Testing

Tested with PowerShell 7.4.6 on Linux against mocked collection APIs; live
Windows WMI/CIM, real remoting and Windows PowerShell 5.1 were not
exercised in that environment. The toolkit targets Windows PowerShell 5.1
and PowerShell 7+ on Windows.

```powershell
# Presentation/export tests + mocked collection tests (run on any OS with PowerShell)
pwsh -File Tests/Run-Tests.ps1          # or: powershell -File Tests/Run-Tests.ps1
pwsh -File Tests/Run-MockedTests.ps1    # collectors, remote registry, orchestrator, runner (mocked CIM/registry)

# Demo report from synthetic data (goes through the real exporter)
pwsh -File Tests/Generate-DemoReport.ps1

# Runtime test of the report JavaScript (requires Node.js)
node Tests/js-smoke-test.js SysAnalyzer-DemoReport.html
```

Verified in this repository: module import and exports on PowerShell 7.4;
report generation through the real exporter for single/multi/empty/hostile
inputs; JSON round-trips; `</script>` and hostile-title escaping; offline
self-containment (no external references); CSV exports; the collectors and
remote-registry paths against mocked CIM and StdRegProv data (including the
WOW6432Node path, missing optional registry values, and access failures);
the runner end-to-end with mocks; a DOM-harness execution of the report
JavaScript across all hosts; and interactive rendering of the demo report
in a real browser (fleet overview, host switching, search, sort, coverage and
error panels, Unicode and hostile-string handling).

**Not verified here** (Linux sandbox): live Windows WMI/CIM collection, remote
fan-out against real hosts, and Windows PowerShell 5.1. Run both test suites
and a real single-host collection (`.\Run-SystemAnalysis.ps1`) on a Windows
machine before fleet use.

## License

Free to use and modify.
