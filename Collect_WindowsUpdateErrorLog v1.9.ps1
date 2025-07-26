param (
    [Parameter(Mandatory = $true)]
    [string]$KBID,

    [Parameter(Mandatory = $true)]
    [string]$computerListPath
)

# Example usage:
# .\Collect_windowsUpdateErrorLog.ps1 -KBID KB5058379 -ComputerPath "cleaned_hostname.txt"

# Paths and Setup
#$computerListPath = "cleaned_hostname.txt"
#$kbFilePath = "kb_list1.txt"
$timestamp      = Get-Date -Format "yyyyMMdd_HHmm"
$htmlReportPath = ".\PatchFailureReport-$timestamp.html"
$csvReportPath = ".\PatchFailureAnalysis-$timestamp.csv"
$unreachableComputer     = ".\UnreachableDevices_$timestamp.txt"
$reachableComputer       = ".\ReachableDevices_$timestamp.txt"
$maxThreads = 20

$reachable = @()
$unreachable = @()


# to remove "" from the path
$cleanPath = $computerListPath.Trim('"')
$computers = Get-Content $cleanPath
$jobs = @()
$results = @()

# Extract Error Codes from Log Text

function Get-ErrorCodesFromText {
    param ($logText, $fullTextMap)
    if (-not $logText) { return "" }
    $codes = Select-String -InputObject $logText -Pattern "0x[0-9A-Fa-f]{8}" -AllMatches | ForEach-Object { $_.Matches.Value }
    $codes = $codes | Sort-Object -Unique
    $html = foreach ($code in $codes) {
        $tooltip = if ($fullTextMap.ContainsKey($code)) { $fullTextMap[$code] } else { "No details available" }
        "<a href='https://learn.microsoft.com/search/?terms=$code' title='$tooltip'>$code</a>"
    }
    return $html -join "<br>"
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
		WindowsUpdateDNS = "N/A"
		WindowsUpdatePort443 = "N/A"
		AllKBInstalled = "N/A"
		Last5KBInstalled ="N/A"

    }

    if ($comp -and $comp.Trim() -ne "" -and (Test-Connection -ComputerName $comp -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
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
				# DNS resolution and ping test to windowsupdate.microsoft.com or update.microsoft.com.
				$winUpdateHost = "windowsupdate.microsoft.com"
				$winUpdateConnectivity = "Unknown"
				$winUpdatePortTest = "Unknown"
				try {
					$dnsResolved = [System.Net.Dns]::GetHostAddresses($winUpdateHost)
					if ($dnsResolved) {
						$winUpdateConnectivity = "Resolved"
						$portTest = Test-NetConnection -ComputerName $winUpdateHost -Port 443 -WarningAction SilentlyContinue
						$winUpdatePortTest = if ($portTest.TcpTestSucceeded) { "Success" } else { "Failed" }
					}
				} catch {
					$winUpdateConnectivity = "Failed"
					$winUpdatePortTest = "Failed"
				}

                $pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
                $kbInstalled = (Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID -eq $kbID }).HotFixID				
				
				## Collecting last 5 HotFix
				$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
				#$kbSummary = foreach ($hf in $hotfixes) {
				#	$dateStr = if ($hf.InstalledOn) { $hf.InstalledOn.ToString("MM/dd/yyyy") } else { "Unknown install date" }
				#	"$($hf.HotFixID) ($dateStr)"
				#} -join "<br>"
                					
								
				$logs = @{
                    ReportingEvents = ""
                    UpdatesDeploymentLog = ""
                    WinUpdateErrors = ""
                }

                if (-not $kbInstalled) {
                    #$logs.ReportingEvents = Get-Content "C:\Windows\SoftwareDistribution\ReportingEvents.log" -ErrorAction SilentlyContinue | Out-String
					#$logs.ReportingEvents = Get-Content "C:\Windows\SoftwareDistribution\ReportingEvents.log" -Tail 50 -ErrorAction SilentlyContinue | Where-Object { $_ -match "KB\\d{7}" -and $_ -match "error|fail|0x[0-9A-Fa-f]{8}" } |ForEach-Object { $_.Trim() } |Out-String
					$logs.ReportingEvents = Get-Content "C:\Windows\SoftwareDistribution\ReportingEvents.log" -ErrorAction SilentlyContinue |
					Where-Object {$_ -match "KB\d{7}" -or $_ -match "0x[0-9A-Fa-f]{8}" -or $_ -match "error|fail" } |
					ForEach-Object {($_.Trim() -split '\}\s+\d{4}-\d{2}-\d{2}.*?\d{3}\s+')[1] -replace '^\[\w+\]\s+\d+\s+\{[^\}]+\}\s+\d+\s+', '' } | Out-String
                    #$logs.UpdatesDeploymentLog = Get-Content "C:\Windows\CCM\Logs\UpdatesDeployment.log" -Tail 50 -ErrorAction SilentlyContinue | Out-String
					$logs.UpdatesDeploymentLog = Get-Content "C:\Windows\CCM\Logs\UpdatesDeployment.log" -Tail 50 -ErrorAction SilentlyContinue | 
					Where-Object { $_ -match "KB\\d{7}" -or $_ -match "0x[0-9A-Fa-f]{8}" -or $_ -match "error|fail" } | ForEach-Object { $_.Trim() } |Out-String
                    #$logs.WinUpdateErrors = Get-WinEvent -FilterHashtable @{LogName='System'; ID=20,25,31,34;StartTime=(Get-Date).AddDays(-14)} -MaxEvents 20 -ErrorAction SilentlyContinue | Select TimeCreated, Id, Message | Out-String
					$logs.WinUpdateErrors = Get-WinEvent -FilterHashtable @{LogName = 'System'; ID = 20,25,31,34; StartTime = (Get-Date).AddDays(-15)} -MaxEvents 20 -ErrorAction SilentlyContinue |
					Select-Object TimeCreated, Id, Message | ForEach-Object {"$($_.TimeCreated) [$($_.Id)] $($_.Message)"} |
					Where-Object {$_ -match "KB\d{7}" -or $_ -match "0x[0-9A-Fa-f]{8}" -or $_ -match "error|fail" } | ForEach-Object { $_.Trim() } | Out-String
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
					WindowsUpdateDNS = $winUpdateConnectivity
					WindowsUpdatePort443 = $winUpdatePortTest
					AllKBInstalled       = $hotfixes

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
				$data.WindowsUpdateDNS = $_.WindowsUpdateDNS
				$data.WindowsUpdatePort443 = $_.WindowsUpdatePort443				
				$AllKBInstalled=$_.AllKBInstalled
				$data.Last5KBInstalled = ($AllKBInstalled | Where-Object { $_.HotFixID -and $_.HotFixID.Trim() -ne "" } | ForEach-Object {
					$dateStr = if ($_.InstalledOn) { $_.InstalledOn.ToString("MM/dd/yyyy") } else { "Unknown install date" }
					"$($_.HotFixID) ($dateStr)"
				}) -join "<br>"

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

Write-Host "... Collecting Data..."
do {
 $completedJobs = Get-Job -State Completed
	foreach ($job in $completedJobs) {
		$output = Receive-Job -Job $job
			if ($output.Reachable -eq "Yes") {		
				$reachable += $output.ComputerName
				Write-Host "$($output.ComputerName) is reachable" -ForegroundColor Green} 
			else {
				$unreachable += $output.ComputerName
				Write-Host "$($output.ComputerName) is unreachable" -ForegroundColor Red}
		$results += $output
		Remove-Job -Job $job }
} while ((Get-Job).Count -gt 0)


# Export CSV with Full Logs
$results | Export-Csv -Path $csvReportPath -NoTypeInformation
$reachable | Set-Content -Path $reachableComputer -Encoding UTF8
$unreachable | Set-Content -Path $unreachableComputer -Encoding UTF8

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


$htmlBody = foreach ($item in $results) {
    $reachableHtml = if ($item.Reachable -eq "Yes") { '<div class="green">Yes</div>' } else { '<div class="red">No</div>' }
    $kbInstalledHtml = if ($item.KBInstalled -eq "Yes") { '<div class="green">Yes</div>' } else { '<div class="red">No</div>' }
	$winUpdateDNSHtml = if ($item.WindowsUpdateDNS -eq "Resolved") { '<div class="green">Resolved</div>' } else { '<div class="red">Failed</div>' }
	$winUpdatePortHtml = if ($item.WindowsUpdatePort443 -eq "Success") { '<div class="green">Success</div>' } else { '<div class="red">Failed</div>' }
	$freespaceGBHTML = if ($item.FreeSpace_GB -lt 20) {"<div class='red'>$($item.FreeSpace_GB)</div>"} else {"$($item.FreeSpace_GB)" }

    $map = @{}
    foreach ($line in ($item.ReportingEvents, $item.UpdatesDeploymentLog, $item.WinUpdateErrors, $item.WindowsUpdateLog)) {
        if ($line) {
            $matches = Select-String -InputObject $line -Pattern "0x[0-9A-Fa-f]{8}" -AllMatches
            foreach ($match in $matches) {
                foreach ($code in $match.Matches.Value) {
                    if (-not $map.ContainsKey($code)) {
                        $map[$code] = $line
                    }
                }
            }
        }
    }
    $reportingErrors = Get-ErrorCodesFromText $item.ReportingEvents $map
    $deploymentErrors = Get-ErrorCodesFromText $item.UpdatesDeploymentLog $map
    $winUpdateErrors = Get-ErrorCodesFromText $item.WinUpdateErrors $map
	
    "<tr>
        <td>$($item.ComputerName)</td>
        <td>$reachableHtml</td>
        <td>$($item.KBTargeted)</td>
        <td>$kbInstalledHtml</td>
		<td>$($item.Last5KBInstalled)</td>
        <td>$($item.WSUSServer)</td>
        <td>$($item.WSUSPingResult)</td>		
		<td>$winUpdateDNSHtml</td>
		<td>$winUpdatePortHtml</td>
        <td>$freespaceGBHTML</td>
        <td>$($item.SCCMCache_GB)</td>
        <td>$($item.PendingReboot)</td>
        <td>$reportingErrors</td>
        <td>$deploymentErrors</td>
        <td>$winUpdateErrors</td>
    </tr>"
}

$htmlTable = @"
<html>
<head>
$htmlHeader
</head>
<body>
<h2>Patch Failure Report</h2>
<table>
    <tr>
        <th>ComputerName</th>
        <th>Reachable</th>
        <th>KBTargeted</th>
        <th>KBInstalled</th>
		<th>Last5KBInstalled</th>
        <th>WSUSServer</th>
        <th>WSUSPingResult</th>		
		<th>WinUpdate DNS</th>
		<th>WinUpdate Port 443</th>
        <th>FreeSpace_GB</th>
        <th>SCCMCache_GB</th>
        <th>PendingReboot</th>
        <th>ReportingEvent_Errors</th>
        <th>UpdatesDeploymentLog_Errors</th>
        <th>WinUpdateErrors_Errors</th>
    </tr>
    $($htmlBody -join "`n")
</table>
</body>
</html>
"@


$htmlTable | Out-File $htmlReportPath -Encoding UTF8


Write-Host "`nReports generated:"
Write-Host " - CSV: $csvReportPath"
Write-Host " - HTML: $htmlReportPath"
Write-Host " - Reachable: $reachableComputer"
Write-Host " - Unreachable: $unreachableComputer"
Write-Host "`nTotal Reachable Devices: $($reachable.Count)"
Write-Host "Total Unreachable Devices: $($unreachable.Count)"
Start-Process $htmlReportPath

Read-Host "Press Enter to exit"
