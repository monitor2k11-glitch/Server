#Requires -Version 5.1
<#
.SYNOPSIS
    SysAnalyzer - Advanced PowerShell system analysis toolkit.

.DESCRIPTION
    Reusable functions for gathering CPU, Memory, Storage, installed
    applications (with versions) and installed patches/hotfixes from a
    single computer or a group of computers, plus a self-contained HTML
    report generator (embedded CSS + JavaScript, no external dependencies).

    Collection and presentation are fully separated:
      - Collectors   : Get-SystemSummary, Get-SystemCPU, Get-SystemMemory,
                       Get-SystemStorage, Get-InstalledApplications,
                       Get-SystemPatches (each accepts -ComputerName or
                       -CimSession for remote use).
      - Orchestrator : Invoke-SystemAnalysis (fan-out, per-category error
                       handling, coverage tracking).
      - Presentation : New-SystemHTMLReport, Export-SystemAnalysisCsv.

    Remote hosts are queried over a single authenticated CIM session per
    host (WinRM with automatic DCOM fallback). Nothing is ever installed
    on remote computers and remoting is never enabled or weakened.

.NOTES
    Targets Windows PowerShell 5.1 and PowerShell 7+ on Windows. Developed
    and tested with PowerShell 7.4.6 on Linux against mocked collection
    APIs: live Windows WMI/CIM, real remoting and Windows PowerShell 5.1
    were not exercised in that environment.

    Some categories (Appx/Store packages, Windows Update history) are only
    available for the local host; when requested for a remote target,
    Windows Update history coverage is recorded as 'Failed' with a note and
    nothing is collected.
#>

Set-StrictMode -Version Latest

# Cache for Get-AnalyzerLocalNames (module script scope).
$script:AnalyzerLocalNames = $null

# ============================================================================
# Private helpers
# ============================================================================

function Test-AnalyzerIsLocal {
    <#
    .SYNOPSIS
        Returns $true when the given computer name refers to the local host.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$ComputerName)

    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $true }
    $n = $ComputerName.Trim()
    if ($n -eq '.' -or $n -ieq 'localhost') { return $true }
    if ($env:COMPUTERNAME -and $n -ieq $env:COMPUTERNAME) { return $true }

    # Exact local hostname/FQDN values only (see Get-AnalyzerLocalNames).
    # A name that merely shares the short-name prefix
    # (HOST01.other-domain.invalid) refers to a DIFFERENT machine and must
    # be treated as remote - matching on the prefix would silently collect
    # the local machine's inventory while labelling it with the requested
    # remote name.
    foreach ($name in @(Get-AnalyzerLocalNames)) {
        if ($name -and $n -ieq $name) { return $true }
    }
    return $false
}

function Get-AnalyzerLocalNames {
    # Private: exact local hostname/FQDN candidates for local-target
    # classification. Never returns a prefix pattern - only full names
    # that resolve to THIS machine. Cached after the first lookup.
    if (-not $script:AnalyzerLocalNames) {
        $names = New-Object System.Collections.Generic.List[string]
        try { $names.Add([string][System.Net.Dns]::GetHostName()) } catch { }
        try {
            $hostEntry = [System.Net.Dns]::GetHostEntry([string][System.Net.Dns]::GetHostName())
            $names.Add([string]$hostEntry.HostName)
            foreach ($alias in @($hostEntry.Aliases)) { $names.Add([string]$alias) }
        } catch { }
        $script:AnalyzerLocalNames = $names.ToArray()
    }
    return @($script:AnalyzerLocalNames)
}

function New-AnalyzerCimSession {
    <#
    .SYNOPSIS
        Creates a CIM session to a remote host. WinRM first, DCOM fallback.
        Returns $null for the local host (callers then use implicit local CIM).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential,
        [int]$OperationTimeoutSec = 60
    )
    if (Test-AnalyzerIsLocal -ComputerName $ComputerName) { return $null }

    $params = @{
        ComputerName         = $ComputerName
        OperationTimeoutSec  = $OperationTimeoutSec
        ErrorAction          = 'Stop'
    }
    if ($Credential) { $params.Credential = $Credential }

    try {
        return (New-CimSession @params)
    }
    catch {
        # Retry once over DCOM (useful when WinRM is firewalled but RPC is open).
        $params.SessionOption = New-CimSessionOption -Protocol Dcom
        return (New-CimSession @params)
    }
}

function Get-AnalyzerCimArgs {
    <#
    .SYNOPSIS
        Builds the common CIM cmdlet parameter splat for a (possibly null) session.
    #>
    param(
        $CimSession,
        [int]$OperationTimeoutSec = 60
    )
    $args_ = @{ OperationTimeoutSec = $OperationTimeoutSec }
    if ($CimSession) { $args_.CimSession = $CimSession }
    return $args_
}

# --- StdRegProv helpers (remote registry access over the CIM session) -------

$script:REG_HKLM = [UInt32]2147483650  # HKEY_LOCAL_MACHINE
$script:REG_HKU  = [UInt32]2147483653  # HKEY_USERS

function Invoke-AnalyzerRegMethod {
    param(
        $CimSession,
        [Parameter(Mandatory)][string]$MethodName,
        [Parameter(Mandatory)][hashtable]$Arguments
    )
    $p = @{
        Namespace   = 'root/default'
        ClassName   = 'StdRegProv'
        MethodName  = $MethodName
        Arguments   = $Arguments
        ErrorAction = 'Stop'
    }
    if ($CimSession) { $p.CimSession = $CimSession }
    Invoke-CimMethod @p
}

function Get-AnalyzerRegSubKeys {
    # Returns the subkey names under Hive\SubKey, or an empty array.
    # ReturnValue 0 with no sNames is an empty key (success, not an error);
    # ReturnValue 2 means the key does not exist; other codes are real
    # failures and throw so the orchestrator records them instead of
    # silently reporting an empty inventory.
    param(
        $CimSession,
        [Parameter(Mandatory)][UInt32]$Hive,
        [AllowEmptyString()][string]$SubKey
    )
    $r = Invoke-AnalyzerRegMethod -CimSession $CimSession -MethodName 'EnumKey' -Arguments @{
        hDefKey = $Hive; sSubKeyName = $SubKey
    }
    if ($r.ReturnValue -eq 0) {
        if ($null -ne $r.sNames) { return @($r.sNames) }
        return @()
    }
    if ($r.ReturnValue -eq 2) { return @() }
    throw "StdRegProv EnumKey failed with code $($r.ReturnValue) for '$SubKey'"
}

function Get-AnalyzerRegValueNames {
    # Returns the value names present under Hive\SubKey.
    param(
        $CimSession,
        [Parameter(Mandatory)][UInt32]$Hive,
        [Parameter(Mandatory)][string]$SubKey
    )
    $r = Invoke-AnalyzerRegMethod -CimSession $CimSession -MethodName 'EnumValues' -Arguments @{
        hDefKey = $Hive; sSubKeyName = $SubKey
    }
    if ($r.ReturnValue -eq 0) {
        if ($null -ne $r.sNames) { return @($r.sNames) }
        return @()
    }
    if ($r.ReturnValue -eq 2) { return @() }
    throw "StdRegProv EnumValues failed with code $($r.ReturnValue) for '$SubKey'"
}

function Get-AnalyzerRegString {
    param(
        $CimSession,
        [Parameter(Mandatory)][UInt32]$Hive,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName
    )
    $r = Invoke-AnalyzerRegMethod -CimSession $CimSession -MethodName 'GetStringValue' -Arguments @{
        hDefKey = $Hive; sSubKeyName = $SubKey; sValueName = $ValueName
    }
    if ($r.ReturnValue -eq 0 -and $null -ne $r.sValue) { return [string]$r.sValue }
    if ($r.ReturnValue -eq 0 -or $r.ReturnValue -eq 2) { return $null }   # empty value / not found
    throw "StdRegProv GetStringValue failed with code $($r.ReturnValue) for '$SubKey\\$ValueName'"
}

function Get-AnalyzerRegDword {
    param(
        $CimSession,
        [Parameter(Mandatory)][UInt32]$Hive,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName
    )
    $r = Invoke-AnalyzerRegMethod -CimSession $CimSession -MethodName 'GetDwordValue' -Arguments @{
        hDefKey = $Hive; sSubKeyName = $SubKey; sValueName = $ValueName
    }
    if ($r.ReturnValue -eq 0 -and $null -ne $r.uValue) { return [UInt32]$r.uValue }
    if ($r.ReturnValue -eq 0 -or $r.ReturnValue -eq 2) { return $null }   # empty value / not found
    throw "StdRegProv GetDwordValue failed with code $($r.ReturnValue) for '$SubKey\\$ValueName'"
}

function Get-AnalyzerNoteProperty {
    # StrictMode-safe property read: returns $null when the property is absent.
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop) { return $prop.Value }
    return $null
}

function New-AnalyzerAppRecord {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Version,
        [string]$Publisher,
        [string]$InstallDate,
        [string]$InstallLocation,
        [double]$SizeMB,
        [Parameter(Mandatory)][string]$Source,
        [string]$UninstallString
    )
    [pscustomobject][ordered]@{
        Name              = $Name
        Version           = $Version
        Publisher         = $Publisher
        InstallDate       = $InstallDate
        InstallLocation   = $InstallLocation
        SizeMB            = $SizeMB
        Source            = $Source
        UninstallString   = $UninstallString
    }
}

function Get-AnalyzerUninstallSubKey {
    return 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
}

function Add-AnalyzerLocalRegistryApps {
    <#
    .SYNOPSIS
        Collects uninstall entries via the local registry provider (fast path).
    #>
    param([System.Collections.Generic.List[object]]$Apps)

    $roots = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';                 Source = 'Machine' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall';    Source = 'Machine (32-bit)' }
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root.Path)) { continue }
        $keyItems = Get-ChildItem $root.Path -ErrorAction SilentlyContinue
        foreach ($keyItem in @($keyItems)) {
            if ($null -eq $keyItem) { continue }   # guard: empty key / null pipeline output
            $p = Get-ItemProperty -Path $keyItem.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $p) { continue }
            $name = Get-AnalyzerNoteProperty -Object $p -Name 'DisplayName'
            if ([string]::IsNullOrWhiteSpace([string]$name)) { continue }
            if ((Get-AnalyzerNoteProperty -Object $p -Name 'SystemComponent') -eq 1) { continue }
            $sizeMB = $null
            $estKB = Get-AnalyzerNoteProperty -Object $p -Name 'EstimatedSize'
            if ($estKB) { $sizeMB = [math]::Round($estKB / 1024, 1) }
            $Apps.Add((New-AnalyzerAppRecord -Name ([string]$name) `
                    -Version ([string](Get-AnalyzerNoteProperty -Object $p -Name 'DisplayVersion')) `
                    -Publisher ([string](Get-AnalyzerNoteProperty -Object $p -Name 'Publisher')) `
                    -InstallDate ([string](Get-AnalyzerNoteProperty -Object $p -Name 'InstallDate')) `
                    -InstallLocation ([string](Get-AnalyzerNoteProperty -Object $p -Name 'InstallLocation')) `
                    -SizeMB $sizeMB -Source $root.Source `
                    -UninstallString ([string](Get-AnalyzerNoteProperty -Object $p -Name 'UninstallString'))))
        }
    }

    # Per-user installs for every profile hive currently loaded under HKEY_USERS.
    $userRoot = 'Registry::HKEY_USERS'
    if (Test-Path $userRoot) {
        $sidKeys = Get-ChildItem $userRoot -ErrorAction SilentlyContinue
        foreach ($sidKey in @($sidKeys)) {
            if ($null -eq $sidKey) { continue }   # guard: empty key / null pipeline output
            $sid = $sidKey.PSChildName
            if ($sid -notmatch '^S-1-5-21-') { continue }   # real user profiles only
            $uPath = "$userRoot\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            if (-not (Test-Path $uPath)) { continue }
            $keyItems = Get-ChildItem $uPath -ErrorAction SilentlyContinue
            foreach ($keyItem in @($keyItems)) {
                if ($null -eq $keyItem) { continue }   # guard: empty key / null pipeline output
                $p = Get-ItemProperty -Path $keyItem.PSPath -ErrorAction SilentlyContinue
                if ($null -eq $p) { continue }
                $name = Get-AnalyzerNoteProperty -Object $p -Name 'DisplayName'
                if ([string]::IsNullOrWhiteSpace([string]$name)) { continue }
                if ((Get-AnalyzerNoteProperty -Object $p -Name 'SystemComponent') -eq 1) { continue }
                $sizeMB = $null
                $estKB = Get-AnalyzerNoteProperty -Object $p -Name 'EstimatedSize'
                if ($estKB) { $sizeMB = [math]::Round($estKB / 1024, 1) }
                $Apps.Add((New-AnalyzerAppRecord -Name ([string]$name) `
                        -Version ([string](Get-AnalyzerNoteProperty -Object $p -Name 'DisplayVersion')) `
                        -Publisher ([string](Get-AnalyzerNoteProperty -Object $p -Name 'Publisher')) `
                        -InstallDate ([string](Get-AnalyzerNoteProperty -Object $p -Name 'InstallDate')) `
                        -InstallLocation ([string](Get-AnalyzerNoteProperty -Object $p -Name 'InstallLocation')) `
                        -SizeMB $sizeMB -Source 'User' `
                        -UninstallString ([string](Get-AnalyzerNoteProperty -Object $p -Name 'UninstallString'))))
            }
        }
    }
}

function Add-AnalyzerRemoteRegistryApps {
    <#
    .SYNOPSIS
        Collects uninstall entries from a remote host via StdRegProv over CIM.
    #>
    param(
        $CimSession,
        [System.Collections.Generic.List[object]]$Apps
    )

    $uninstallKey = Get-AnalyzerUninstallSubKey
    $roots = @(
        @{ SubKey = $uninstallKey;                                Source = 'Machine' },
        @{ SubKey = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Source = 'Machine (32-bit)' }
    )
    foreach ($root in $roots) {
        $subKeys = Get-AnalyzerRegSubKeys -CimSession $CimSession -Hive $script:REG_HKLM -SubKey $root.SubKey
        foreach ($subKey in @($subKeys)) {
            $fullKey = "$($root.SubKey)\$subKey"
            Add-AnalyzerRemoteUninstallEntry -CimSession $CimSession -Apps $Apps `
                -FullKey $fullKey -Hive $script:REG_HKLM -Source $root.Source
        }
    }

    # Per-user installs (only for profile hives currently loaded under HKU).
    $sids = Get-AnalyzerRegSubKeys -CimSession $CimSession -Hive $script:REG_HKU -SubKey ''
    foreach ($sid in @($sids)) {
        if ($sid -notmatch '^S-1-5-21-') { continue }
        $userRootKey = "$sid\$uninstallKey"
        $subKeys = Get-AnalyzerRegSubKeys -CimSession $CimSession -Hive $script:REG_HKU -SubKey $userRootKey
        foreach ($subKey in @($subKeys)) {
            $fullKey = "$userRootKey\$subKey"
            Add-AnalyzerRemoteUninstallEntry -CimSession $CimSession -Apps $Apps `
                -FullKey $fullKey -Hive $script:REG_HKU -Source 'User'
        }
    }
}

function Add-AnalyzerRemoteUninstallEntry {
    param(
        $CimSession,
        [System.Collections.Generic.List[object]]$Apps,
        [Parameter(Mandatory)][string]$FullKey,
        [Parameter(Mandatory)][UInt32]$Hive,
        [Parameter(Mandatory)][string]$Source
    )
    $valueNames = Get-AnalyzerRegValueNames -CimSession $CimSession -Hive $Hive -SubKey $FullKey

    if ($valueNames -contains 'SystemComponent') {
        $sc = Get-AnalyzerRegDword -CimSession $CimSession -Hive $Hive -SubKey $FullKey -ValueName 'SystemComponent'
        if ($sc -eq 1) { return }
    }
    $name = $null
    if ($valueNames -contains 'DisplayName') {
        $name = Get-AnalyzerRegString -CimSession $CimSession -Hive $Hive -SubKey $FullKey -ValueName 'DisplayName'
    }
    if ([string]::IsNullOrWhiteSpace($name)) { return }

    $version = $null; $publisher = $null; $installDate = $null; $location = $null; $uninstall = $null; $sizeMB = $null
    if ($valueNames -contains 'DisplayVersion') {
        $version = Get-AnalyzerRegString -CimSession $CimSession -Hive $Hive -SubKey $FullKey -ValueName 'DisplayVersion'
    }
    if ($valueNames -contains 'Publisher') {
        $publisher = Get-AnalyzerRegString -CimSession $CimSession -Hive $Hive -SubKey $FullKey -ValueName 'Publisher'
    }
    if ($valueNames -contains 'InstallDate') {
        $installDate = Get-AnalyzerRegString -CimSession $CimSession -Hive $Hive -SubKey $FullKey -ValueName 'InstallDate'
    }
    if ($valueNames -contains 'InstallLocation') {
        $location = Get-AnalyzerRegString -CimSession $CimSession -Hive $Hive -SubKey $FullKey -ValueName 'InstallLocation'
    }
    if ($valueNames -contains 'UninstallString') {
        $uninstall = Get-AnalyzerRegString -CimSession $CimSession -Hive $Hive -SubKey $FullKey -ValueName 'UninstallString'
    }
    if ($valueNames -contains 'EstimatedSize') {
        $kb = Get-AnalyzerRegDword -CimSession $CimSession -Hive $Hive -SubKey $FullKey -ValueName 'EstimatedSize'
        if ($null -ne $kb) { $sizeMB = [math]::Round($kb / 1024, 1) }
    }

    $Apps.Add((New-AnalyzerAppRecord -Name $name -Version $version -Publisher $publisher `
            -InstallDate $installDate -InstallLocation $location -SizeMB $sizeMB `
            -Source $Source -UninstallString $uninstall))
}

function Add-AnalyzerAppxApps {
    <#
    .SYNOPSIS
        Adds Microsoft Store / Appx packages (local host only).
    .DESCRIPTION
        Tries -AllUsers first (requires elevation); falls back to the current
        user. Throws on total failure so the caller can record the error.
    #>
    param([System.Collections.Generic.List[object]]$Apps)
    $packages = $null
    $scoped = $null
    try {
        $packages = Get-AppxPackage -AllUsers -ErrorAction Stop
        $scoped = 'all users'
    }
    catch {
        Write-Verbose "Get-AppxPackage -AllUsers unavailable ($($_.Exception.Message)); falling back to current user."
        $packages = Get-AppxPackage -ErrorAction Stop
        $scoped = 'current user only'
    }
    foreach ($pkg in @($packages)) {
        $pkgName = Get-AnalyzerNoteProperty -Object $pkg -Name 'Name'
        if ([string]::IsNullOrWhiteSpace([string]$pkgName)) { continue }
        $Apps.Add((New-AnalyzerAppRecord -Name ([string]$pkgName) `
                -Version ([string](Get-AnalyzerNoteProperty -Object $pkg -Name 'Version')) `
                -Publisher ([string](Get-AnalyzerNoteProperty -Object $pkg -Name 'Publisher')) `
                -InstallDate $null -InstallLocation ([string](Get-AnalyzerNoteProperty -Object $pkg -Name 'InstallLocation')) `
                -SizeMB $null -Source 'Store/Appx' -UninstallString $null))
    }
    return $scoped
}

# ============================================================================
# Collectors - each works locally, remotely via -ComputerName or -CimSession
# ============================================================================

function Get-SystemSummary {
<#
.SYNOPSIS
    Gathers host identity, operating system, BIOS and uptime information.

.DESCRIPTION
    Returns a single object with computer identity (name, domain,
    manufacturer, model, serial), BIOS details, operating system details
    (caption, version, build, architecture, install date, last boot),
    current uptime and time zone.

.PARAMETER ComputerName
    Target a remote computer (a temporary CIM session is created).

.PARAMETER CimSession
    Use an existing CIM session.

.EXAMPLE
    Get-SystemSummary -ComputerName WEBSRV01
#>
    [CmdletBinding(DefaultParameterSetName = 'Remote')]
    param(
        [Parameter(ParameterSetName = 'Remote', Position = 0)][string]$ComputerName,
        [Parameter(ParameterSetName = 'Session')]$CimSession,
        [int]$OperationTimeoutSec = 60
    )

    $session = $CimSession
    $ownsSession = $false
    if (-not $session -and $ComputerName -and -not (Test-AnalyzerIsLocal -ComputerName $ComputerName)) {
        $session = New-AnalyzerCimSession -ComputerName $ComputerName -OperationTimeoutSec $OperationTimeoutSec
        $ownsSession = $true
    }
    try {
        $cimArgs = Get-AnalyzerCimArgs -CimSession $session -OperationTimeoutSec $OperationTimeoutSec

        $cs = Get-CimInstance @cimArgs -ClassName Win32_ComputerSystem
        $os = Get-CimInstance @cimArgs -ClassName Win32_OperatingSystem
        $bios = Get-CimInstance @cimArgs -ClassName Win32_BIOS
        $tz = Get-CimInstance @cimArgs -ClassName Win32_TimeZone

        $localTime = $os.LocalDateTime
        if ($null -eq $localTime) { $localTime = Get-Date }
        $uptime = $null
        if ($os.LastBootUpTime) {
            $uptime = $localTime - $os.LastBootUpTime
        }

        [pscustomobject][ordered]@{
            ComputerName        = [string]$cs.Name
            Domain               = [string]$cs.Domain
            Workgroup           = if ($cs.PartOfDomain) { $null } else { [string]$cs.Domain }
            Manufacturer        = [string]$cs.Manufacturer
            Model               = [string]$cs.Model
            SerialNumber        = [string]$bios.SerialNumber
            BIOSVersion         = [string]$bios.SMBIOSBIOSVersion
            BIOSReleaseDate     = $bios.ReleaseDate
            OSName              = [string]$os.Caption
            OSVersion           = [string]$os.Version
            OSBuildNumber       = [string]$os.BuildNumber
            OSArchitecture      = [string]$os.OSArchitecture
            RegisteredUser      = [string]$os.RegisteredUser
            SystemDrive         = [string]$os.SystemDrive
            InstallDate         = $os.InstallDate
            LastBootUpTime      = $os.LastBootUpTime
            LocalDateTime       = $localTime
            Uptime               = if ($uptime) { [string]::Format('{0:d\.hh\:mm\:ss}', $uptime) } else { $null }
            TimeZone             = [string]$tz.Caption
            LogonUser           = [string]$cs.UserName
        }
    }
    finally {
        if ($ownsSession -and $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Get-SystemCPU {
<#
.SYNOPSIS
    Gathers processor inventory and current utilization.

.DESCRIPTION
    Returns total core/logical processor counts, current total utilization
    percentage and a list of physical processor objects.

.EXAMPLE
    Get-SystemCPU
    Get-SystemCPU -ComputerName WEBSRV01
#>
    [CmdletBinding(DefaultParameterSetName = 'Remote')]
    param(
        [Parameter(ParameterSetName = 'Remote', Position = 0)][string]$ComputerName,
        [Parameter(ParameterSetName = 'Session')]$CimSession,
        [int]$OperationTimeoutSec = 60
    )

    $session = $CimSession
    $ownsSession = $false
    if (-not $session -and $ComputerName -and -not (Test-AnalyzerIsLocal -ComputerName $ComputerName)) {
        $session = New-AnalyzerCimSession -ComputerName $ComputerName -OperationTimeoutSec $OperationTimeoutSec
        $ownsSession = $true
    }
    try {
        $cimArgs = Get-AnalyzerCimArgs -CimSession $session -OperationTimeoutSec $OperationTimeoutSec

        $processors = Get-CimInstance @cimArgs -ClassName Win32_Processor
        $util = $null
        try {
            $perf = Get-CimInstance @cimArgs -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name = '_Total'"
            if ($perf -and $null -ne $perf.PercentProcessorTime) { $util = [int]$perf.PercentProcessorTime }
        } catch { Write-Verbose "CPU utilization query failed: $($_.Exception.Message)" }

        $totalCores = 0; $totalLogical = 0
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($p in @($processors)) {
            if ($p.NumberOfCores)     { $totalCores += [int]$p.NumberOfCores }
            if ($p.NumberOfLogicalProcessors) { $totalLogical += [int]$p.NumberOfLogicalProcessors }
            $list.Add([pscustomobject][ordered]@{
                Name                    = [string]$p.Name
                Manufacturer            = [string]$p.Manufacturer
                MaxClockSpeedMHz        = $p.MaxClockSpeed
                CurrentClockSpeedMHz    = $p.CurrentClockSpeed
                NumberOfCores           = $p.NumberOfCores
                NumberOfLogicalProcessors = $p.NumberOfLogicalProcessors
                L2CacheSizeKB           = $p.L2CacheSize
                L3CacheSizeKB            = $p.L3CacheSize
                SocketDesignation       = [string]$p.SocketDesignation
                Architecture            = [string]$p.Description
            })
        }

        [pscustomobject][ordered]@{
            TotalCores             = $totalCores
            TotalLogicalProcessors  = $totalLogical
            UtilizationPercent      = $util
            Processors              = $list.ToArray()
        }
    }
    finally {
        if ($ownsSession -and $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Get-SystemMemory {
<#
.SYNOPSIS
    Gathers physical memory inventory and current usage.

.DESCRIPTION
    Returns total/available/used memory with a usage percentage, the list
    of installed DIMMs (capacity, speed, part number, location) and page
    file usage.

.EXAMPLE
    Get-SystemMemory
    Get-SystemMemory -ComputerName WEBSRV01
#>
    [CmdletBinding(DefaultParameterSetName = 'Remote')]
    param(
        [Parameter(ParameterSetName = 'Remote', Position = 0)][string]$ComputerName,
        [Parameter(ParameterSetName = 'Session')]$CimSession,
        [int]$OperationTimeoutSec = 60
    )

    $session = $CimSession
    $ownsSession = $false
    if (-not $session -and $ComputerName -and -not (Test-AnalyzerIsLocal -ComputerName $ComputerName)) {
        $session = New-AnalyzerCimSession -ComputerName $ComputerName -OperationTimeoutSec $OperationTimeoutSec
        $ownsSession = $true
    }
    try {
        $cimArgs = Get-AnalyzerCimArgs -CimSession $session -OperationTimeoutSec $OperationTimeoutSec

        $os = Get-CimInstance @cimArgs -ClassName Win32_OperatingSystem
        $modules = Get-CimInstance @cimArgs -ClassName Win32_PhysicalMemory
        $pageFiles = Get-CimInstance @cimArgs -ClassName Win32_PageFileUsage

        $totalBytes = $null; $availBytes = $null; $usedPct = $null
        if ($null -ne $os.TotalVisibleMemorySize -and $os.TotalVisibleMemorySize -ge 0) {
            $totalBytes = [uint64]$os.TotalVisibleMemorySize * 1KB
            if ($null -ne $os.FreePhysicalMemory -and $os.FreePhysicalMemory -ge 0) {
                $availBytes = [uint64]$os.FreePhysicalMemory * 1KB
                if ($totalBytes -gt 0) { $usedPct = [math]::Round((($totalBytes - $availBytes) / $totalBytes) * 100, 1) }
            }
        }

        $modList = New-Object System.Collections.Generic.List[object]
        foreach ($m in @($modules)) {
            $modList.Add([pscustomobject][ordered]@{
                DeviceLocator = [string]$m.DeviceLocator
                BankLabel     = [string]$m.BankLabel
                CapacityBytes = [uint64]$m.Capacity
                SpeedMHz      = $m.Speed
                Manufacturer  = [string]$m.Manufacturer
                PartNumber    = [string]$m.PartNumber
                SerialNumber  = [string]$m.SerialNumber
                FormFactor    = $m.FormFactor
            })
        }
        $pfList = New-Object System.Collections.Generic.List[object]
        foreach ($pf in @($pageFiles)) {
            $pfList.Add([pscustomobject][ordered]@{
                Name             = [string]$pf.Name
                AllocatedSizeMB  = $pf.AllocatedBaseSize
                CurrentUsageMB   = $pf.CurrentUsage
                PeakUsageMB      = $pf.PeakUsage
            })
        }

        [pscustomobject][ordered]@{
            TotalBytes     = $totalBytes
            AvailableBytes = $availBytes
            UsedPercent    = $usedPct
            Modules        = $modList.ToArray()
            PageFiles      = $pfList.ToArray()
        }
    }
    finally {
        if ($ownsSession -and $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Get-SystemStorage {
<#
.SYNOPSIS
    Gathers fixed disk volumes and physical disk inventory.

.DESCRIPTION
    Returns every fixed logical volume (letter, label, file system, size,
    free space, usage percentage), physical disks (model, interface,
    size, partitions) and fleet totals.

.EXAMPLE
    Get-SystemStorage
    Get-SystemStorage -ComputerName WEBSRV01
#>
    [CmdletBinding(DefaultParameterSetName = 'Remote')]
    param(
        [Parameter(ParameterSetName = 'Remote', Position = 0)][string]$ComputerName,
        [Parameter(ParameterSetName = 'Session')]$CimSession,
        [int]$OperationTimeoutSec = 60
    )

    $session = $CimSession
    $ownsSession = $false
    if (-not $session -and $ComputerName -and -not (Test-AnalyzerIsLocal -ComputerName $ComputerName)) {
        $session = New-AnalyzerCimSession -ComputerName $ComputerName -OperationTimeoutSec $OperationTimeoutSec
        $ownsSession = $true
    }
    try {
        $cimArgs = Get-AnalyzerCimArgs -CimSession $session -OperationTimeoutSec $OperationTimeoutSec

        $disks = Get-CimInstance @cimArgs -ClassName Win32_LogicalDisk -Filter "DriveType = 3"
        $phys  = Get-CimInstance @cimArgs -ClassName Win32_DiskDrive

        $volList = New-Object System.Collections.Generic.List[object]
        $totalBytes = [uint64]0; $freeBytes = [uint64]0
        foreach ($d in @($disks)) {
            $size = [uint64]$d.Size
            $free = [uint64]$d.FreeSpace
            $usedPct = $null
            if ($size -gt 0) { $usedPct = [math]::Round((($size - $free) / $size) * 100, 1) }
            $volList.Add([pscustomobject][ordered]@{
                DeviceID    = [string]$d.DeviceID
                VolumeName  = [string]$d.VolumeName
                FileSystem  = [string]$d.FileSystem
                SizeBytes   = $size
                FreeBytes   = $free
                UsedPercent = $usedPct
            })
            $totalBytes += $size; $freeBytes += $free
        }

        $physList = New-Object System.Collections.Generic.List[object]
        foreach ($p in @($phys)) {
            $physList.Add([pscustomobject][ordered]@{
                Index         = $p.Index
                Model         = [string]$p.Model
                InterfaceType = [string]$p.InterfaceType
                MediaType     = [string]$p.MediaType
                SizeBytes     = [uint64]$p.Size
                Partitions    = $p.Partitions
                SerialNumber  = [string]$p.SerialNumber
            })
        }

        [pscustomobject][ordered]@{
            Volumes        = $volList.ToArray()
            PhysicalDisks  = $physList.ToArray()
            TotalBytes     = $totalBytes
            FreeBytes      = $freeBytes
        }
    }
    finally {
        if ($ownsSession -and $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Get-InstalledApplications {
<#
.SYNOPSIS
    Gathers installed applications with versions from one computer.

.DESCRIPTION
    Inventory is registry-based (Add/Remove Programs entries) and covers:
      - Machine-wide 64-bit installs (HKLM ... Uninstall)
      - Machine-wide 32-bit installs (HKLM ... WOW6432Node Uninstall)
      - Per-user installs for every loaded profile hive (HKU)
    SystemComponent (hidden) entries are skipped. Win32_Product is
    deliberately NOT used because it triggers MSI self-repair.

    -IncludeAppx adds Microsoft Store / Appx packages (local host only).

    An empty result genuinely means "no matching registry entries" and is
    not an error; provenance is tracked by the Source field of each entry.

.PARAMETER ComputerName
    Target a remote computer (a temporary CIM session is created).

.PARAMETER CimSession
    Use an existing CIM session.

.EXAMPLE
    Get-InstalledApplications
    Get-InstalledApplications -ComputerName WEBSRV01
    Get-InstalledApplications -IncludeAppx
#>
    [CmdletBinding(DefaultParameterSetName = 'Remote')]
    param(
        [Parameter(ParameterSetName = 'Remote', Position = 0)][string]$ComputerName,
        [Parameter(ParameterSetName = 'Session')]$CimSession,
        [switch]$IncludeAppx,
        [int]$OperationTimeoutSec = 120
    )

    $session = $CimSession
    $ownsSession = $false
    $isLocal = $true
    if (-not $session -and $ComputerName) {
        $isLocal = Test-AnalyzerIsLocal -ComputerName $ComputerName
        if (-not $isLocal) {
            $session = New-AnalyzerCimSession -ComputerName $ComputerName -OperationTimeoutSec $OperationTimeoutSec
            $ownsSession = $true
        }
    }
    elseif ($session) {
        $isLocal = Test-AnalyzerIsLocal -ComputerName $session.ComputerName
    }

    try {
        $apps = New-Object System.Collections.Generic.List[object]
        if ($isLocal) {
            Add-AnalyzerLocalRegistryApps -Apps $apps
        }
        else {
            Add-AnalyzerRemoteRegistryApps -CimSession $session -Apps $apps
        }
        if ($IncludeAppx) {
            if ($isLocal) {
                try {
                    $scoped = Add-AnalyzerAppxApps -Apps $apps
                    Write-Warning "Appx packages enumerated ($scoped)."
                }
                catch {
                    Write-Warning "Appx/Store package enumeration failed: $($_.Exception.Message)"
                }
            }
            else { Write-Warning 'Appx/Store packages can only be enumerated on the local host; skipped for remote targets.' }
        }
        return $apps.ToArray()
    }
    finally {
        if ($ownsSession -and $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Get-SystemPatches {
<#
.SYNOPSIS
    Gathers installed patches / hotfixes from one computer.

.DESCRIPTION
    Source is the Quick Fix Engineering (QFE) list
    (Win32_QuickFixEngineering, the same data as Get-HotFix). Microsoft
    documents that this class "returns only the updates supplied by
    Component Based Servicing (CBS)", so some installed updates never
    appear in it. For a fuller picture on the local host, pair this with
    Get-WindowsUpdateHistory (separate, clearly-labelled history data -
    installation events, not a guaranteed current installed-state inventory).

.PARAMETER ComputerName
    Target a remote computer (a temporary CIM session is created).

.PARAMETER CimSession
    Use an existing CIM session.

.EXAMPLE
    Get-SystemPatches
    Get-SystemPatches -ComputerName WEBSRV01
#>
    [CmdletBinding(DefaultParameterSetName = 'Remote')]
    param(
        [Parameter(ParameterSetName = 'Remote', Position = 0)][string]$ComputerName,
        [Parameter(ParameterSetName = 'Session')]$CimSession,
        [int]$OperationTimeoutSec = 60
    )

    $session = $CimSession
    $ownsSession = $false
    $isLocal = $true
    if (-not $session -and $ComputerName) {
        $isLocal = Test-AnalyzerIsLocal -ComputerName $ComputerName
        if (-not $isLocal) {
            $session = New-AnalyzerCimSession -ComputerName $ComputerName -OperationTimeoutSec $OperationTimeoutSec
            $ownsSession = $true
        }
    }
    elseif ($session) {
        $isLocal = Test-AnalyzerIsLocal -ComputerName $session.ComputerName
    }

    try {
        $cimArgs = Get-AnalyzerCimArgs -CimSession $session -OperationTimeoutSec $OperationTimeoutSec
        $patches = New-Object System.Collections.Generic.List[object]

        $qfe = Get-CimInstance @cimArgs -ClassName Win32_QuickFixEngineering
        foreach ($q in @($qfe)) {
            $patches.Add([pscustomobject][ordered]@{
                Id          = [string]$q.HotFixID
                Description = [string]$q.Description
                InstalledOn = $q.InstalledOn
                InstalledBy = [string]$q.InstalledBy
                Source      = 'QFE'
                Result      = [string](Get-AnalyzerNoteProperty -Object $q -Name 'FixComments')
            })
        }

        # Most recent first.
        $sorted = @($patches | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue)
        return $sorted
    }
    finally {
        if ($ownsSession -and $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Get-WindowsUpdateHistory {
<#
.SYNOPSIS
    Gathers the local Windows Update installation history (local host only).

.DESCRIPTION
    Reads the Windows Update Agent history (Microsoft.Update.Session COM)
    and returns *installation events* that completed successfully. This is
    clearly-labelled history data, NOT a guaranteed current installed-state
    inventory: a successful installation may later have been superseded or
    removed, and successful uninstall operations are excluded by filtering
    to Operation = 1 (Installation) with ResultCode 2/3. Use Get-SystemPatches
    (QFE) for the installed-patch inventory and treat this as complementary
    evidence.

    Requires the local host (the WUA COM API is not remotely accessible).

.EXAMPLE
    Get-WindowsUpdateHistory
#>
    [CmdletBinding()]
    param()

    $entries = New-Object System.Collections.Generic.List[object]
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $searcher = $updateSession.CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()
    if ($count -le 0) { return $entries.ToArray() }

    $history = $searcher.QueryHistory(0, $count)
    $resultNames = @{ 1 = 'In Progress'; 2 = 'Succeeded'; 3 = 'Succeeded (with errors)'; 4 = 'Failed'; 5 = 'Aborted' }
    $operationNames = @{ 1 = 'Installation'; 2 = 'Uninstallation' }
    foreach ($entry in @($history)) {
        $code = [int]$entry.ResultCode
        $operation = Get-AnalyzerNoteProperty -Object $entry -Name 'Operation'
        # Installation events only, and only those that completed.
        if ($operation -ne 1) { continue }
        if ($code -ne 2 -and $code -ne 3) { continue }
        $resultText = if ($resultNames.ContainsKey($code)) { $resultNames[$code] } else { "Code $code" }
        $entries.Add([pscustomobject][ordered]@{
            Id          = [string]$entry.Title
            Description = 'Windows Update installation event'
            InstalledOn = $entry.Date
            InstalledBy = [string](Get-AnalyzerNoteProperty -Object $entry -Name 'ClientApplicationID')
            Source      = 'WindowsUpdate (history)'
            Result      = "$resultText$(if ($entry.HResult -ne 0) { ' (0x' + ('{0:X8}' -f [int]$entry.HResult) + ')' })"
        })
    }
    $sorted = @($entries | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue)
    return $sorted
}

# ============================================================================
# Orchestrator
# ============================================================================

function Invoke-SystemAnalysis {
<#
.SYNOPSIS
    Runs a full system analysis against one computer or a group of computers.

.DESCRIPTION
    For every computer the following categories are collected and returned
    in a single, consistent object: Summary, CPU, Memory, Storage,
    Applications (with versions) and Patches.

    Robustness features:
      - One authenticated CIM session per host, used for every category.
      - Per-category error handling: a failing category never aborts the
        host; successful categories are preserved and the failure is
        recorded in CollectionErrors.
      - Coverage tracking per category: Complete / Partial / Failed /
        NotRequested, with human-readable notes explaining scope limits
        (e.g. Appx packages are local-host only; QFE does not list every
        update).
      - Bounded parallel fan-out on PowerShell 7+ (-ThrottleLimit,
        default 8); sequential fallback on Windows PowerShell 5.1 or with
        -Sequential.

    Unreachable hosts return a result object with Status 'Unreachable'
    and the connection error - never an exception.

.PARAMETER ComputerName
    One or more computers. Defaults to the local host.

.PARAMETER Credential
    Optional credentials for remote CIM sessions.

.PARAMETER ThrottleLimit
    Maximum concurrent hosts (PowerShell 7+ parallel mode).

.PARAMETER IncludeAppx
    Include Microsoft Store/Appx packages (local host only).

.PARAMETER IncludeWindowsUpdates
    Include the Windows Update installation-event history as a separate
    UpdateHistory category (local host only; remote hosts are skipped with a
    coverage note). This is history, NOT the installed-patch inventory - see
    the notes in Get-SystemPatches.

.PARAMETER Sequential
    Force sequential collection (also the default on PowerShell 5.1).

.PARAMETER OperationTimeoutSec
    Per-CIM-operation timeout in seconds.

.EXAMPLE
    Invoke-SystemAnalysis

.EXAMPLE
    Invoke-SystemAnalysis -ComputerName WEBSRV01, DBSRV02, APPSRV03 -Credential (Get-Credential)

.EXAMPLE
    $results = Invoke-SystemAnalysis -ComputerName (Get-Content servers.txt) -ThrottleLimit 16
    New-SystemHTMLReport -AnalysisResult $results -Path .\FleetReport.html
#>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName = @($env:COMPUTERNAME),
        [pscredential]$Credential,
        [ValidateRange(1, 128)][int]$ThrottleLimit = 8,
        [switch]$IncludeAppx,
        [switch]$IncludeWindowsUpdates,
        [switch]$Sequential,
        [ValidateRange(5, 3600)][int]$OperationTimeoutSec = 60
    )

    # Normalise and de-duplicate the target list.
    $targets = New-Object System.Collections.Generic.List[string]
    foreach ($c in $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $t = $c.Trim()
        if (-not $targets.Contains($t)) { $targets.Add($t) }
    }
    if ($targets.Count -eq 0) { $targets.Add($env:COMPUTERNAME) }

    # PowerShell 7+: bounded parallel fan-out (each runspace re-imports the
    # module and runs the single-host sequential path).
    if ($targets.Count -gt 1 -and -not $Sequential -and $PSVersionTable.PSVersion.Major -ge 7) {
        $modulePath = $MyInvocation.MyCommand.Module.Path
        Write-Verbose "Parallel fan-out over $($targets.Count) hosts (throttle $ThrottleLimit)."
        $results = $targets | ForEach-Object -Parallel {
            Import-Module $using:modulePath -Force -WarningAction SilentlyContinue
            Invoke-SystemAnalysis -ComputerName $_ `
                -Credential $using:Credential `
                -IncludeAppx:$using:IncludeAppx `
                -IncludeWindowsUpdates:$using:IncludeWindowsUpdates `
                -Sequential `
                -OperationTimeoutSec $using:OperationTimeoutSec `
                -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        } -ThrottleLimit $ThrottleLimit
        return @($results | Sort-Object -Property ComputerName)
    }

    # Sequential path (also the single-host worker for parallel mode).
    $allResults = New-Object System.Collections.Generic.List[object]
    foreach ($target in $targets) {
        $allResults.Add((Invoke-AnalyzerSingleHost -ComputerName $target -Credential $Credential `
                -IncludeAppx ([bool]$IncludeAppx.IsPresent) -IncludeWindowsUpdates ([bool]$IncludeWindowsUpdates.IsPresent) `
                -OperationTimeoutSec $OperationTimeoutSec))
    }
    return $allResults.ToArray()
}

function Invoke-AnalyzerSingleHost {
    # Private: collects every category from a single host with per-category
    # error handling and coverage tracking.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential,
        [bool]$IncludeAppx = $false,
        [bool]$IncludeWindowsUpdates = $false,
        [int]$OperationTimeoutSec = 60
    )

    $isLocal = Test-AnalyzerIsLocal -ComputerName $ComputerName

    $result = [pscustomobject][ordered]@{
        ComputerName     = $ComputerName
        Timestamp        = (Get-Date)
        Status           = 'Success'
        Summary          = $null
        Cpu              = $null
        Memory           = $null
        Storage          = $null
        Applications     = @()
        Patches          = @()
        UpdateHistory    = @()
        Coverage         = [ordered]@{}
        CoverageNotes    = [ordered]@{}
        CollectionErrors = @()
    }

    $session = $null
    if (-not $isLocal) {
        try {
            $session = New-AnalyzerCimSession -ComputerName $ComputerName -Credential $Credential -OperationTimeoutSec $OperationTimeoutSec
        }
        catch {
            $result.Status = 'Unreachable'
            $result.CollectionErrors = @("Connection failed: $($_.Exception.Message)")
            foreach ($cat in 'Summary', 'CPU', 'Memory', 'Storage', 'Applications', 'Patches', 'UpdateHistory') {
                $result.Coverage[$cat] = 'Failed'
            }
            return $result
        }
    }

    try {
        # ---- Summary ---------------------------------------------------
        try {
            $result.Summary = Get-SystemSummary -CimSession $session -OperationTimeoutSec $OperationTimeoutSec -ErrorAction Stop
            $result.Coverage['Summary'] = 'Complete'
        }
        catch {
            $result.Status = 'Partial'
            $result.Coverage['Summary'] = 'Failed'
            $result.CollectionErrors += "Summary: $($_.Exception.Message)"
        }

        # ---- CPU --------------------------------------------------------
        try {
            $result.Cpu = Get-SystemCPU -CimSession $session -OperationTimeoutSec $OperationTimeoutSec -ErrorAction Stop
            $result.Coverage['CPU'] = 'Complete'
        }
        catch {
            $result.Status = 'Partial'
            $result.Coverage['CPU'] = 'Failed'
            $result.CollectionErrors += "CPU: $($_.Exception.Message)"
        }

        # ---- Memory -----------------------------------------------------
        try {
            $result.Memory = Get-SystemMemory -CimSession $session -OperationTimeoutSec $OperationTimeoutSec -ErrorAction Stop
            $result.Coverage['Memory'] = 'Complete'
        }
        catch {
            $result.Status = 'Partial'
            $result.Coverage['Memory'] = 'Failed'
            $result.CollectionErrors += "Memory: $($_.Exception.Message)"
        }

        # ---- Storage ----------------------------------------------------
        try {
            $result.Storage = Get-SystemStorage -CimSession $session -OperationTimeoutSec $OperationTimeoutSec -ErrorAction Stop
            $result.Coverage['Storage'] = 'Complete'
        }
        catch {
            $result.Status = 'Partial'
            $result.Coverage['Storage'] = 'Failed'
            $result.CollectionErrors += "Storage: $($_.Exception.Message)"
        }

        # ---- Applications -------------------------------------------------
        try {
            $appWarnings = $null
            $result.Applications = @(Get-InstalledApplications -CimSession $session `
                    -IncludeAppx:($IncludeAppx -and $isLocal) `
                    -OperationTimeoutSec $OperationTimeoutSec -ErrorAction Stop `
                    -WarningAction SilentlyContinue -WarningVariable appWarnings)
            $result.Coverage['Applications'] = 'Partial'
            if (-not $isLocal) {
                $result.CoverageNotes['Applications'] =
                    'Registry-based inventory (machine-wide + loaded user profiles). ' +
                    'Appx/Store packages are not collected from remote hosts. ' +
                    'Portable/unregistered software and apps in unloaded profiles are invisible to this method.'
            }
            elseif (-not $IncludeAppx) {
                $result.CoverageNotes['Applications'] =
                    'Registry-based inventory (machine-wide + loaded user profiles). ' +
                    'Appx/Store packages not included (rerun with -IncludeAppx). ' +
                    'Portable/unregistered software and apps in unloaded profiles are invisible to this method.'
            }
            else {
                $result.CoverageNotes['Applications'] =
                    'Registry-based inventory (machine-wide + loaded user profiles) plus Appx/Store packages. ' +
                    'Portable/unregistered software and apps in unloaded profiles are invisible to this method.'
            }
            foreach ($w in @($appWarnings)) {
                $result.CoverageNotes['Applications'] += " Note: $w"
            }
        }
        catch {
            $result.Status = 'Partial'
            $result.Coverage['Applications'] = 'Failed'
            $result.CollectionErrors += "Applications: $($_.Exception.Message)"
        }

        # ---- Patches ------------------------------------------------------
        try {
            $patchWarnings = $null
            $result.Patches = @(Get-SystemPatches -CimSession $session `
                    -OperationTimeoutSec $OperationTimeoutSec -ErrorAction Stop `
                    -WarningAction SilentlyContinue -WarningVariable patchWarnings)
            # QFE never lists every update (some CBS/servicing-stack updates are
            # not registered), so patch coverage is reported as Partial.
            $result.Coverage['Patches'] = 'Partial'
            $result.CoverageNotes['Patches'] =
                'Quick Fix Engineering (QFE) installed-patch list. Microsoft documents ' +
                'that this class "returns only the updates supplied by Component Based ' +
                'Servicing (CBS)", so some installed updates never appear in it.'
            foreach ($w in @($patchWarnings)) {
                $result.CoverageNotes['Patches'] += " Note: $w"
            }
        }
        catch {
            $result.Status = 'Partial'
            $result.Coverage['Patches'] = 'Failed'
            $result.CollectionErrors += "Patches: $($_.Exception.Message)"
        }

        # ---- Windows Update history (separate, clearly labelled) -------------
        # This is installation-event history, NOT the installed-patch inventory,
        # so it is kept out of $result.Patches and patch counts.
        if ($IncludeWindowsUpdates) {
            if ($isLocal) {
                try {
                    $result.UpdateHistory = @(Get-WindowsUpdateHistory -ErrorAction Stop)
                    $result.Coverage['UpdateHistory'] = 'Partial'
                    $result.CoverageNotes['UpdateHistory'] =
                        'Windows Update installation-event history (successful installations only). ' +
                        'This is history, not a guaranteed current installed-state inventory: ' +
                        'updates may later have been superseded or removed.'
                }
                catch {
                    $result.Status = 'Partial'
                    $result.Coverage['UpdateHistory'] = 'Failed'
                    $result.CollectionErrors += "UpdateHistory: $($_.Exception.Message)"
                }
            }
            else {
                $result.Coverage['UpdateHistory'] = 'Failed'
                $result.CoverageNotes['UpdateHistory'] =
                    'Windows Update history is only readable on the local host; not collected from remote targets.'
            }
        }
        else {
            $result.Coverage['UpdateHistory'] = 'NotRequested'
            $result.CoverageNotes['UpdateHistory'] =
                'Rerun with -IncludeWindowsUpdates to include the local Windows Update installation history.'
        }

        # Promote to Failed when nothing at all could be collected.
        $failedCount = 0
        foreach ($cat in 'Summary', 'CPU', 'Memory', 'Storage', 'Applications', 'Patches') {
            if ($result.Coverage[$cat] -eq 'Failed') { $failedCount++ }
        }
        if ($failedCount -ge 6) { $result.Status = 'Failed' }

        return $result
    }
    finally {
        if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

# ============================================================================
# Presentation
# ============================================================================

function New-SystemHTMLReport {
<#
.SYNOPSIS
    Generates a fully self-contained HTML report from analysis results.

.DESCRIPTION
    Produces a single .html file with all CSS, JavaScript and data embedded
    - no CDN, fonts, images or network requests of any kind. The report
    works offline, supports host switching, searchable and sortable
    application/patch tables, CSV export of visible rows, capacity bars
    and visible collection errors and per-category coverage.

    All data is embedded as JSON (escaped against </script> breakout) and
    rendered exclusively via DOM APIs / textContent, so collected strings
    can never inject HTML or script.

.PARAMETER AnalysisResult
    Output of Invoke-SystemAnalysis (single result or array).

.PARAMETER Path
    Output file path.

.PARAMETER Title
    Report title.

.EXAMPLE
    New-SystemHTMLReport -AnalysisResult $results -Path .\Report.html -Title 'Monthly Fleet Audit'
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$AnalysisResult,
        [string]$Path = (Join-Path -Path (Get-Location).Path -ChildPath 'SystemAnalysisReport.html'),
        [string]$Title = 'System Analysis Report',
        [switch]$PassThru
    )

    begin { $collected = New-Object System.Collections.Generic.List[object] }
    process {
        foreach ($item in @($AnalysisResult)) {
            if ($null -ne $item) { $collected.Add($item) }
        }
    }
    end {
        $templatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Assets/ReportTemplate.html'
        if (-not (Test-Path -Path $templatePath)) {
            throw "Report template not found: $templatePath"
        }

        # Normalise each host object: guarantee arrays for Applications,
        # Patches and UpdateHistory so single/zero results survive JSON
        # round-trips.
        $hosts = New-Object System.Collections.Generic.List[object]
        foreach ($h in $collected) {
            # Tolerate result objects created before UpdateHistory existed.
            if (-not $h.PSObject.Properties['UpdateHistory']) {
                $h | Add-Member NoteProperty UpdateHistory @()
            }
            $h.Applications = @(@($h.Applications) | Where-Object { $null -ne $_ })
            $h.Patches = @(@($h.Patches) | Where-Object { $null -ne $_ })
            $h.UpdateHistory = @(@($h.UpdateHistory) | Where-Object { $null -ne $_ })
            $hosts.Add($h)
        }

        $payload = [ordered]@{
            title        = $Title
            generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            hosts        = $hosts.ToArray()
        }

        # JSON with </script> breakout prevention and line-separator escapes.
        $json = ConvertTo-Json -InputObject $payload -Depth 14
        $json = $json -replace '</', '<\/'
        $json = $json -replace ([string][char]0x2028), '\u2028'
        $json = $json -replace ([string][char]0x2029), '\u2029'

        $html = [System.IO.File]::ReadAllText($templatePath)
        # HTML-encode the title for markup insertion (the visible topbar title
        # is set separately via textContent in the report JavaScript).
        $titleEncoded = [System.Net.WebUtility]::HtmlEncode($Title)
        $html = $html.Replace('__REPORT_TITLE__', $titleEncoded).Replace('__REPORT_DATA__', $json)

        # Resolve the path against the PowerShell current location before
        # handing it to the .NET file API.
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $outDir = Split-Path -Path $resolvedPath -Parent
        if ($outDir -and -not (Test-Path -Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        [System.IO.File]::WriteAllText($resolvedPath, $html, [System.Text.UTF8Encoding]::new($false))

        Write-Host "Report written: $resolvedPath"
        if ($PassThru) { return (Get-Item -Path $resolvedPath) }
    }
}

function Export-SystemAnalysisCsv {
<#
.SYNOPSIS
    Exports analysis results to CSV files (one per host and category).

.DESCRIPTION
    Creates, under the given directory:
      <COMPUTER>_Applications.csv  - all applications with versions
      <COMPUTER>_Patches.csv       - all patches/hotfixes
      <COMPUTER>_UpdateHistory.csv - Windows Update installation events
      <COMPUTER>_Summary.csv       - summary + coverage + errors
    Files are omitted for hosts where a category failed or is empty.

.EXAMPLE
    Export-SystemAnalysisCsv -AnalysisResult $results -OutputDirectory .\Csv
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$AnalysisResult,
        [string]$OutputDirectory = (Join-Path -Path (Get-Location).Path -ChildPath 'Csv')
    )

    begin { $collected = New-Object System.Collections.Generic.List[object] }
    process {
        foreach ($item in @($AnalysisResult)) {
            if ($null -ne $item) { $collected.Add($item) }
        }
    }
    end {
        if (-not (Test-Path -Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }
        $files = New-Object System.Collections.Generic.List[string]

        foreach ($h in $collected) {
            $safeName = ($h.ComputerName -replace '[^A-Za-z0-9_.-]', '_')
            if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = 'UNKNOWN_HOST' }

            if (@($h.Applications).Count -gt 0) {
                $p = Join-Path $OutputDirectory "$safeName`_Applications.csv"
                @($h.Applications) | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
                $files.Add($p)
            }
            if (@($h.Patches).Count -gt 0) {
                $p = Join-Path $OutputDirectory "$safeName`_Patches.csv"
                @($h.Patches) | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
                $files.Add($p)
            }
            if (@($h.UpdateHistory).Count -gt 0) {
                $p = Join-Path $OutputDirectory "$safeName`_UpdateHistory.csv"
                @($h.UpdateHistory) | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
                $files.Add($p)
            }
            $flat = [pscustomobject][ordered]@{
                ComputerName     = $h.ComputerName
                Status           = $h.Status
                Timestamp        = $h.Timestamp
                ApplicationCount = @($h.Applications).Count
                PatchCount       = @($h.Patches).Count
                CoverageSummary  = (($h.Coverage.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
                CollectionErrors = (@($h.CollectionErrors) -join ' | ')
            }
            $p = Join-Path $OutputDirectory "$safeName`_Summary.csv"
            $flat | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
            $files.Add($p)
        }
        Write-Host "CSV files written to $OutputDirectory ($($files.Count) file(s))."
        return $files
    }
}

Export-ModuleMember -Function @(
    'Get-SystemSummary'
    'Get-SystemCPU'
    'Get-SystemMemory'
    'Get-SystemStorage'
    'Get-InstalledApplications'
    'Get-SystemPatches'
    'Get-WindowsUpdateHistory'
    'Invoke-SystemAnalysis'
    'New-SystemHTMLReport'
    'Export-SystemAnalysisCsv'
)
