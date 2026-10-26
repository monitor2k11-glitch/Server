<#
.SYNOPSIS
    End-to-end runner for the SysAnalyzer toolkit.

.DESCRIPTION
    Runs a full analysis against one computer or a group of computers and
    generates a self-contained HTML report plus optional CSV exports.

.EXAMPLE
    .\Run-SystemAnalysis.ps1

.EXAMPLE
    .\Run-SystemAnalysis.ps1 -ComputerName WEBSRV01, DBSRV02 -Credential (Get-Credential)

.EXAMPLE
    .\Run-SystemAnalysis.ps1 -ComputerName (Get-Content .\servers.txt) -ThrottleLimit 16 -OutputPath .\Fleet.html
#>
[CmdletBinding()]
param(
    # One or more computer names (or a single one). Defaults to the local host.
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    # Optional credentials for remote hosts (WinRM or DCOM).
    [pscredential]$Credential,

    # Where to write the HTML report.
    [string]$OutputPath = (Join-Path (Get-Location).Path 'SystemAnalysisReport.html'),

    # Report title shown in the browser tab and top bar.
    [string]$Title = 'System Analysis Report',

    # Include Microsoft Store / Appx packages (local host only).
    [switch]$IncludeAppx,

    # Include Windows Update history in addition to QFE (local host only).
    [switch]$IncludeWindowsUpdates,

    # Directory for per-host CSV exports (omitted entirely with -NoCsv).
    [string]$CsvDirectory,

    [switch]$NoCsv,

    # Maximum concurrent hosts on PowerShell 7+ (default 8).
    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 8,

    # Force sequential collection (also default on PowerShell 5.1).
    [switch]$Sequential,

    # Per-CIM-operation timeout in seconds.
    [int]$OperationTimeoutSec = 60
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'SysAnalyzer.psd1'
Import-Module $modulePath -Force

# Resolve output locations against the PowerShell current location early.
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

Write-Host "==> Analysing $($ComputerName.Count) host(s): $($ComputerName -join ', ')"

# Only forward parameters that Invoke-SystemAnalysis actually accepts.
$invokeParams = @{}
foreach ($key in 'ComputerName', 'Credential', 'IncludeAppx', 'IncludeWindowsUpdates',
                 'ThrottleLimit', 'Sequential', 'OperationTimeoutSec') {
    if ($PSBoundParameters.ContainsKey($key)) { $invokeParams[$key] = $PSBoundParameters[$key] }
}
$results = Invoke-SystemAnalysis @invokeParams

$okCount      = @($results | Where-Object { $_.Status -eq 'Success' }).Count
$partialCount = @($results | Where-Object { $_.Status -eq 'Partial' }).Count
$badCount     = @($results | Where-Object { $_.Status -in 'Failed', 'Unreachable' }).Count
Write-Host "==> Collection finished: $okCount ok, $partialCount partial, $badCount failed/unreachable."

New-SystemHTMLReport -AnalysisResult $results -Path $OutputPath -Title $Title

if (-not $NoCsv) {
    if (-not $CsvDirectory) {
        $CsvDirectory = Join-Path (Split-Path -Parent $OutputPath) 'Csv'
    }
    $CsvDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvDirectory)
    Export-SystemAnalysisCsv -AnalysisResult $results -OutputDirectory $CsvDirectory | Out-Null
}

Write-Host "==> Done. HTML report: $OutputPath"
if ($results.Count -gt 0) {
    Write-Host '    Open the report in any browser - it is fully self-contained and works offline.'
}
