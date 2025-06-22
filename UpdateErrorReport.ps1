
# Enhanced_Collect_WindowsUpdateErrors.ps1
# Collects update error data, disk space, SCCM cache, WSUS connectivity, and generates CSV and HTML reports

$computerListPath = "C:\Temp\failed_devices.txt"
$kbID = "KB5055518"
$wsusServer = "http://wsusserver:8530"
$htmlReportPath = "C:\Temp\PatchFailureReport.html"
$csvReportPath = "C:\Temp\PatchFailureAnalysis.csv"

$results = @()

$computers = Get-Content $computerListPath

foreach ($comp in $computers) {
    Write-Host "Processing $comp..." -ForegroundColor Cyan

    if (Test-Connection -ComputerName $comp -Count 1 -Quiet) {
        try {
            $data = Invoke-Command -ComputerName $comp -ScriptBlock {
                $reportingEvents = Get-Content "C:\Windows\SoftwareDistribution\ReportingEvents.log" -ErrorAction SilentlyContinue |
                    Select-String -Pattern $using:kbID | Out-String

                $ccmLogs = Get-Content "C:\Windows\CCM\Logs\UpdatesDeployment.log" -Tail 50 -ErrorAction SilentlyContinue | Out-String

                $wuErrors = Get-WinEvent -FilterHashtable @{LogName='System'; ID=20,25,31,34} -MaxEvents 10 -ErrorAction SilentlyContinue |
                    Select TimeCreated, Id, Message | Out-String

                $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
                $freeSpaceGB = "{0:N2}" -f ($disk.FreeSpace / 1GB)

                $cachePath = "C:\Windows\ccmcache"
                $cacheSizeMB = if (Test-Path $cachePath) {
                    "{0:N2}" -f ((Get-ChildItem $cachePath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB)
                } else { "N/A" }

                $wsusTest = Test-NetConnection -ComputerName "wsusserver" -Port 8530 -WarningAction SilentlyContinue

                $pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

                return [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    FreeSpace_GB = $freeSpaceGB
                    SCCMCache_MB = $cacheSizeMB
                    ReportingEvents = $reportingEvents.Trim()
                    UpdatesDeploymentLog = $ccmLogs.Trim()
                    WinUpdateErrors = $wuErrors.Trim()
                    WSUS_Ping = $wsusTest.PingSucceeded
                    WSUS_TCP_Connected = $wsusTest.TcpTestSucceeded
                    PendingReboot = $pendingReboot
                }
            }

            $results += $data
        } catch {
            Write-Warning "Failed to collect data from $comp. Error: $_"
        }
    } else {
        Write-Warning "$comp is not reachable."
    }
}

# Export to CSV
$results | Export-Csv -Path $csvReportPath -NoTypeInformation

# Export to HTML
$results |
    Select-Object ComputerName, FreeSpace_GB, SCCMCache_MB, WSUS_Ping, WSUS_TCP_Connected, PendingReboot,
        @{Name="ReportingEvents";Expression={($_.ReportingEvents -replace "`n", "<br>")}},
        @{Name="UpdatesDeploymentLog";Expression={($_.UpdatesDeploymentLog -replace "`n", "<br>")}},
        @{Name="WinUpdateErrors";Expression={($_.WinUpdateErrors -replace "`n", "<br>")}} |
    ConvertTo-Html -Property ComputerName, FreeSpace_GB, SCCMCache_MB, WSUS_Ping, WSUS_TCP_Connected, PendingReboot,
        ReportingEvents, UpdatesDeploymentLog, WinUpdateErrors `
    -Head '<style>table {border-collapse: collapse; width: 100%; font-family: Segoe UI; font-size: 12px;} th, td {border: 1px solid #ccc; padding: 6px;} th {background-color: #f2f2f2;}</style>' `
    -Title "Patch Failure Report" |
    Out-File $htmlReportPath

Write-Host "✅ Report generation completed:"
Write-Host " - CSV: $csvReportPath"
Write-Host " - HTML: $htmlReportPath" -ForegroundColor Green
