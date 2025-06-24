# Paths and Setup
$computerListPath = "C:\Temp\failed_devices.txt"
$kbFilePath = "C:\Temp\KB.txt"
$htmlReportPath = "C:\Temp\PatchFailureReport.html"
$csvReportPath = "C:\Temp\PatchFailureAnalysis.csv"
$maxThreads = 10

# Read KB to Check
if (-Not (Test-Path $kbFilePath)) { Write-Error "KB.txt missing at $kbFilePath"; exit }
$kbID = Get-Content $kbFilePath | Select-Object -First 1

# Read Device List
$computers = Get-Content $computerListPath
$jobs = @()
$results = @()

# Extract Error Codes from Log Text
function Get-ErrorCodesFromText {
    param ($logText)
    if (-not $logText) { return "" }
    $codes = Select-String -InputObject $logText -Pattern "0x[0-9A-Fa-f]{8}" -AllMatches | ForEach-Object { $_.Matches.Value }
    return ($codes | Sort-Object -Unique) -join ", "
}

# Scriptblock for Remote Collection
$scriptBlock = {
    param($comp, $kbID)

    $data = [PSCustomObject]@{
        ComputerName = $comp
        Reachable = "No"
        KBTargeted = $kbID
        KBInstalled = "Unknown"
        WSUSServer = "N/A"
        WSUSPingResult = "N/A"
        FreeSpace_GB = "N/A"
        SCCMCache_GB = "N/A"
        PendingReboot = "N/A"
        ReportingEvents = ""
        UpdatesDeploymentLog = ""
        WinUpdateErrors = ""
    }

    if (Test-Connection -ComputerName $comp -Count 1 -Quiet) {
        $data.Reachable = "Yes"

        try {
            Invoke-Command -ComputerName $comp -ScriptBlock {
                param($kbID)

                function Get-WSUSServerFromRegistry {
                    try {
                        $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                        $server = Get-ItemProperty -Path $key -ErrorAction Stop | Select-Object -ExpandProperty WUServer
                        return $server
                    } catch { return "Not Configured" }
                }

                $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
                $freeSpaceGB = "{0:N2}" -f ($disk.FreeSpace / 1GB)
                $cachePath = "C:\Windows\ccmcache"
                $cacheSizeGB = if (Test-Path $cachePath) {
                    "{0:N2}" -f ((Get-ChildItem $cachePath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB)
                } else { "N/A" }
                $wsus = Get-WSUSServerFromRegistry
                $wsusHost = ""; $wsusPort = ""; $wsusPingResult = "N/A"
                if ($wsus -ne "Not Configured") {
                    try {
                        $wsusUri = [System.Uri]$wsus
                        $wsusHost = $wsusUri.Host
                        $wsusPort = $wsusUri.Port
                        $pingResult = Test-NetConnection -ComputerName $wsusHost -Port $wsusPort -WarningAction SilentlyContinue
                        $wsusPingResult = if ($pingResult.TcpTestSucceeded) { "Success" } else { "Failed" }
                    } catch { $wsusPingResult = "Invalid WSUS URL or Test Failed" }
                }
                $pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
                $kbInstalled = (Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID -eq $kbID }).HotFixID

                $logs = @{
                    ReportingEvents = ""
                    UpdatesDeploymentLog = ""
                    WinUpdateErrors = ""
                }

                if (-not $kbInstalled) {
                    $logs.ReportingEvents = Get-Content "C:\Windows\SoftwareDistribution\ReportingEvents.log" -ErrorAction SilentlyContinue | Out-String
                    $logs.UpdatesDeploymentLog = Get-Content "C:\Windows\CCM\Logs\UpdatesDeployment.log" -Tail 50 -ErrorAction SilentlyContinue | Out-String
                    $logs.WinUpdateErrors = Get-WinEvent -FilterHashtable @{LogName='System'; ID=20,25,31,34} -MaxEvents 10 -ErrorAction SilentlyContinue | Select TimeCreated, Id, Message | Out-String
                }

                return [PSCustomObject]@{
                    FreeSpace_GB = $freeSpaceGB
                    SCCMCache_GB = $cacheSizeGB
                    WSUSServer = $wsus
                    WSUSPingResult = $wsusPingResult
                    PendingReboot = $pendingReboot
                    KBInstalled = if ($kbInstalled) { "Yes" } else { "No" }
                    ReportingEvents = $logs.ReportingEvents.Trim()
                    UpdatesDeploymentLog = $logs.UpdatesDeploymentLog.Trim()
                    WinUpdateErrors = $logs.WinUpdateErrors.Trim()
                }
            } -ArgumentList $kbID -ErrorAction Stop | ForEach-Object {
                $data.FreeSpace_GB = $_.FreeSpace_GB
                $data.SCCMCache_GB = $_.SCCMCache_GB
                $data.WSUSServer = $_.WSUSServer
                $data.WSUSPingResult = $_.WSUSPingResult
                $data.PendingReboot = $_.PendingReboot
                $data.KBInstalled = $_.KBInstalled
                $data.ReportingEvents = $_.ReportingEvents
                $data.UpdatesDeploymentLog = $_.UpdatesDeploymentLog
                $data.WinUpdateErrors = $_.WinUpdateErrors
            }
        } catch {
            $data.ReportingEvents = "Failed to connect or collect remote data"
        }
    }
    return $data
}

# Launch Jobs with Thread Control
foreach ($comp in $computers) {
    while (@(Get-Job -State Running).Count -ge $maxThreads) { Start-Sleep -Seconds 2 }

    Start-Job -ScriptBlock $scriptBlock -ArgumentList $comp, $kbID | Out-Null
}

# Collect Results with Real-Time Status
Write-Host "⏳ Collecting Data..."
do {
    $completedJobs = Get-Job -State Completed
    foreach ($job in $completedJobs) {
        $output = Receive-Job -Job $job
        if ($output.Reachable -eq "Yes") {
            Write-Host "✔️  $($output.ComputerName) is reachable" -ForegroundColor Green
        } else {
            Write-Host "❌ $($output.ComputerName) is unreachable" -ForegroundColor Red
        }
        $results += $output
        Remove-Job -Job $job
    }
    Start-Sleep -Seconds 2
} while ((Get-Job).Count -gt 0)

# Export CSV with Full Logs
$results | Export-Csv -Path $csvReportPath -NoTypeInformation

# Build Clean HTML Report
$htmlHeader = @'
<style>
table { border-collapse: collapse; width: 100%; font-family: Segoe UI; font-size: 12px; }
th, td { border: 1px solid #ccc; padding: 6px; vertical-align: top; }
th { background-color: #f2f2f2; }
.green { background-color: #d4edda; }
.red { background-color: #f8d7da; }
</style>
'@

$results | Select-Object ComputerName,
    @{Name="Reachable"; Expression={ if ($_.Reachable -eq "Yes") { '<div class="green">Yes</div>' } else { '<div class="red">No</div>' } }},
    KBTargeted, KBInstalled, WSUSServer, WSUSPingResult, FreeSpace_GB, SCCMCache_GB, PendingReboot,
    @{Name="ReportingEvent_Errors"; Expression={ Get-ErrorCodesFromText $_.ReportingEvents }},
    @{Name="UpdatesDeploymentLog_Errors"; Expression={ Get-ErrorCodesFromText $_.UpdatesDeploymentLog }},
    @{Name="WinUpdateErrors_Errors"; Expression={ Get-ErrorCodesFromText $_.WinUpdateErrors }} |
    ConvertTo-Html -Property * -Head $htmlHeader -Title "Patch Failure Report" |
    Out-File $htmlReportPath

Write-Host "`n✅ Reports generated:"
Write-Host " - CSV: $csvReportPath"
Write-Host " - HTML: $htmlReportPath"
