# Define parameters
$kbID = "KB5055518"
$deviceListPath = ".\devicelist.txt"
$outputHtml = ".\UpdateFailureReport.html"
$maxThreads = 5

# Load device list
$computers = Get-Content -Path $deviceListPath | Where-Object { $_ -and $_.Trim() -ne "" }

# Prepare result collection
$results = @()

# Create runspace pool
$sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)
$runspacePool.Open()

# Script block to run on each remote computer
$scriptBlock = {
    param($computer, $kbID)

    $result = [PSCustomObject]@{
        ComputerName      = $computer
        KBInstalled       = "Unknown"
        ServicesStatus    = ""
        FreeSpaceGB       = 0
        LowDiskWarning    = ""
        PendingReboot     = "Unknown"
        UpdateErrorLog    = "N/A"
        LogEntry          = "N/A"
        Reachable         = $true
        Error             = ""
    }

    try {
        if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Reachable = $false
            return $result
        }

        Invoke-Command -ComputerName $computer -ScriptBlock {
            param($kbID)
            $res = [PSCustomObject]@{
                KBInstalled       = "No"
                ServicesStatus    = ""
                FreeSpaceGB       = 0
                LowDiskWarning    = ""
                PendingReboot     = "No"
                UpdateErrorLog    = ""
                LogEntry          = ""
            }

            if (Get-HotFix -Id $kbID -ErrorAction SilentlyContinue) {
                $res.KBInstalled = "Yes"
            }

            $services = @("wuauserv", "bits", "trustedinstaller", "ccmexec")
            $status = foreach ($svc in $services) {
                try {
                    $s = Get-Service -Name $svc -ErrorAction Stop
                    "$svc:$($s.Status)"
                } catch {
                    "$svc:NotFound"
                }
            }
            $res.ServicesStatus = $status -join ", "

            $cDrive = Get-PSDrive C
            $freeGB = [math]::Round($cDrive.Free / 1GB, 2)
            $res.FreeSpaceGB = $freeGB
            if ($freeGB -lt 5) {
                $res.LowDiskWarning = "Yes"
            }

            $rebootKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
            )
            foreach ($key in $rebootKeys) {
                if (Test-Path $key) {
                    $res.PendingReboot = "Yes"
                    break
                }
            }

            $logPath = "C:\Windows\CCM\Logs\WUAHandler.log"
            if (Test-Path $logPath) {
                $lines = Get-Content $logPath -Tail 100 | Select-String -Pattern $kbID
                if ($lines) {
                    $res.LogEntry = ($lines | Select-Object -First 1).ToString()
                } else {
                    $res.LogEntry = "No log entry"
                }
            } else {
                $res.LogEntry = "Log not found"
            }

            $event = Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (Level=2)]]" -MaxEvents 1
            if ($event) {
                $res.UpdateErrorLog = $event.Message
            }

            return $res
        } -ArgumentList $kbID -ErrorAction Stop | ForEach-Object {
            $result.KBInstalled    = $_.KBInstalled
            $result.ServicesStatus = $_.ServicesStatus
            $result.FreeSpaceGB    = $_.FreeSpaceGB
            $result.LowDiskWarning = $_.LowDiskWarning
            $result.PendingReboot  = $_.PendingReboot
            $result.UpdateErrorLog = $_.UpdateErrorLog
            $result.LogEntry       = $_.LogEntry
        }

    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# Create and manage runspaces
$jobs = @()
foreach ($computer in $computers) {
    $powershell = [powershell]::Create()
    $powershell.RunspacePool = $runspacePool
    $null = $powershell.AddScript($scriptBlock).AddArgument($computer).AddArgument($kbID)
    $job = [PSCustomObject]@{
        Pipe     = $powershell
        Async    = $powershell.BeginInvoke()
        Computer = $computer
    }
    $jobs += $job
}

# Wait for jobs and collect results
foreach ($job in $jobs) {
    try {
        $output = $job.Pipe.EndInvoke($job.Async)
        foreach ($entry in $output) {
            $results += $entry
        }
    } catch {
        $results += [PSCustomObject]@{
            ComputerName = $job.Computer
            Error        = $_.Exception.Message
        }
    }
    $job.Pipe.Dispose()
}

# HTML formatting with color coding
$htmlHeader = @"
<style>
table { font-family: Arial; border-collapse: collapse; width: 100%; }
td, th { border: 1px solid #ddd; padding: 8px; text-align: left; }
tr:nth-child(even) { background-color: #f2f2f2; }
tr:hover { background-color: #ddd; }
.success { background-color: #d4edda; }
.warning { background-color: #fff3cd; }
.error { background-color: #f8d7da; }
</style>
<h2>Windows Update Diagnostic Report</h2>
"@

# Build the HTML rows
$htmlRows = foreach ($item in $results | Sort-Object ComputerName) {
    $class = "success"
    if ($item.KBInstalled -ne "Yes" -or $item.LowDiskWarning -eq "Yes" -or $item.PendingReboot -eq "Yes" -or $item.Reachable -eq $false -or $item.Error) {
        $class = if ($item.Reachable -eq $false -or $item.Error) { "error" }
                 elseif ($item.LowDiskWarning -eq "Yes" -or $item.PendingReboot -eq "Yes") { "warning" }
                 else { "error" }
    }

    "<tr class='$class'>
        <td>$($item.ComputerName)</td>
        <td>$($item.KBInstalled)</td>
        <td>$($item.ServicesStatus)</td>
        <td>$($item.FreeSpaceGB)</td>
        <td>$($item.LowDiskWarning)</td>
        <td>$($item.PendingReboot)</td>
        <td>$($item.UpdateErrorLog)</td>
        <td>$($item.LogEntry)</td>
        <td>$($item.Reachable)</td>
        <td>$($item.Error)</td>
    </tr>"
}

# Combine and export to HTML
$html = @"
$htmlHeader
<table>
<tr>
    <th>ComputerName</th>
    <th>KBInstalled</th>
    <th>ServicesStatus</th>
    <th>FreeSpaceGB</th>
    <th>LowDiskWarning</th>
    <th>PendingReboot</th>
    <th>UpdateErrorLog</th>
    <th>LogEntry</th>
    <th>Reachable</th>
    <th>Error</th>
</tr>
$htmlRows
</table>
"@

Set-Content -Path $outputHtml -Value $html -Encoding UTF8
Write-Host "✅ HTML report saved to: $outputHtml"
