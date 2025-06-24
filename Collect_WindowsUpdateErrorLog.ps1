# Parallel Collection with Jobs

$computerListPath = "C:\Temp\failed_devices.txt"
$kbFilePath = "C:\Temp\KB.txt"
$htmlReportPath = "C:\Temp\PatchFailureReport.html"
$csvReportPath = "C:\Temp\PatchFailureAnalysis.csv"

if (-Not (Test-Path $kbFilePath)) { Write-Error "KB.txt missing at $kbFilePath"; exit }
$kbID = Get-Content $kbFilePath | Select-Object -First 1
$computers = Get-Content $computerListPath
$maxThreads = 10

$jobs = @()
$results = @()

function Collect-DeviceData {
    param($comp, $kbID)

    if (Test-Connection -ComputerName $comp -Count 1 -Quiet) {
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
                $reportingEvents = Get-Content "C:\Windows\SoftwareDistribution\ReportingEvents.log" -ErrorAction SilentlyContinue | Select-String -Pattern $kbID | Out-String
                $ccmLogs = Get-Content "C:\Windows\CCM\Logs\UpdatesDeployment.log" -Tail 50 -ErrorAction SilentlyContinue | Out-String
                $wuErrors = Get-WinEvent -FilterHashtable @{LogName='System'; ID=20,25,31,34} -MaxEvents 10 -ErrorAction SilentlyContinue | Select TimeCreated, Id, Message | Out-String

                return [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    KBTargeted = $kbID
                    KBInstalled = if ($kbInstalled) { "Yes" } else { "No" }
                    WSUSServer = $wsus
                    WSUSPingResult = $wsusPingResult
                    FreeSpace_GB = $freeSpaceGB
                    SCCMCache_GB = $cacheSizeGB
                    PendingReboot = $pendingReboot
                    ReportingEvents = $reportingEvents.Trim()
                    UpdatesDeploymentLog = $ccmLogs.Trim()
                    WinUpdateErrors = $wuErrors.Trim()
                }
            } -ArgumentList $kbID
        } catch { Write-Warning "Error on $comp: $_" }
    }
}

foreach ($comp in $computers) {
    while (@(Get-Job -State Running).Count -ge $maxThreads) { Start-Sleep -Seconds 2 }

    $jobs += Start-Job -ScriptBlock {
        param($c, $k)
        Collect-DeviceData -comp $c -kbID $k
    } -ArgumentList $comp, $kbID
}

# Wait for all jobs
Write-Host "⏳ Waiting for jobs to complete..."
Wait-Job -Job $jobs
$results = $jobs | ForEach-Object {
    Receive-Job -Job $_
    Remove-Job -Job $_
}

# Export results
$results | Export-Csv -Path $csvReportPath -NoTypeInformation

# Build HTML with expandable sections
$htmlHeader = @'
<style>
table { border-collapse: collapse; width: 100%; font-family: Segoe UI; font-size: 12px; }
th, td { border: 1px solid #ccc; padding: 6px; vertical-align: top; }
th { background-color: #f2f2f2; }
details { margin-top: 5px; }
summary { font-weight: bold; cursor: pointer; }
</style>
'@

$results | Select-Object ComputerName, KBTargeted, KBInstalled, WSUSServer, WSUSPingResult, FreeSpace_GB, SCCMCache_GB, PendingReboot,
    @{Name="ReportingEvents";Expression={ "<details><summary>View</summary><pre>$($_.ReportingEvents)</pre></details>" }},
    @{Name="UpdatesDeploymentLog";Expression={ "<details><summary>View</summary><pre>$($_.UpdatesDeploymentLog)</pre></details>" }},
    @{Name="WinUpdateErrors";Expression={ "<details><summary>View</summary><pre>$($_.WinUpdateErrors)</pre></details>" }} |
    ConvertTo-Html -Property * -Head $htmlHeader -Title "Patch Failure Report" |
    Out-File $htmlReportPath

Write-Host "✅ Reports generated:"
Write-Host " - CSV: $csvReportPath"
Write-Host " - HTML: $htmlReportPath"
