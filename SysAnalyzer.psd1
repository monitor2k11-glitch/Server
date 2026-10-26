@{
    RootModule            = 'SysAnalyzer.psm1'
    ModuleVersion          = '1.0.0'
    GUID                  = '8f2b6c1d-4a9e-4c7d-9b3a-5e6d0f1a2c34'
    Author                = 'SysAnalyzer Toolkit'
    CompanyName           = 'SysAnalyzer Toolkit'
    Copyright             = '(c) SysAnalyzer Toolkit. Free to use and modify.'
    Description           = 'Advanced system analysis toolkit: reusable collectors for CPU, memory, storage, installed applications and patches from one computer or a group of computers, plus a fully self-contained HTML report generator and CSV export.'
    PowerShellVersion     = '5.1'
    FunctionsToExport     = @(
        'Get-SystemSummary',
        'Get-SystemCPU',
        'Get-SystemMemory',
        'Get-SystemStorage',
        'Get-InstalledApplications',
        'Get-SystemPatches',
        'Get-WindowsUpdateHistory',
        'Invoke-SystemAnalysis',
        'New-SystemHTMLReport',
        'Export-SystemAnalysisCsv'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    FileList              = @(
        'SysAnalyzer.psm1',
        'SysAnalyzer.psd1',
        'Assets/ReportTemplate.html'
    )
    PrivateData           = @{
        PSData = @{
            Tags = @('inventory', 'report', 'html', 'audit', 'fleet', 'windows')
        }
    }
}
