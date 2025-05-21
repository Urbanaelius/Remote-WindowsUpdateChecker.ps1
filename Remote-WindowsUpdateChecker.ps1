# Define parameters
$kbID = "KB5055518"
$deviceListPath = ".\devicelist.txt"
$outputCsv = ".\UpdateFailureReport.csv"
$maxThreads = 5

# Load device list
$computers = Get-Content -Path $deviceListPath | Where-Object { $_ -and $_.Trim() -ne "" }

# Prepare result collection
$results = [System.Collections.Concurrent.ConcurrentBag[Object]]::new()

# Create runspace pool
$sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)
$runspacePool.Open()

# Helper function to run on remote machine
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

            # Check if update is installed
            if (Get-HotFix -Id $kbID -ErrorAction SilentlyContinue) {
                $res.KBInstalled = "Yes"
            }

            # Check service statuses
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

            # Free space check
            $cDrive = Get-PSDrive C
            $freeGB = [math]::Round($cDrive.Free / 1GB, 2)
            $res.FreeSpaceGB = $freeGB
            if ($freeGB -lt 5) {
                $res.LowDiskWarning = "Yes"
            }

            # Pending Reboot
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

            # WUAHandler.log scan
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

            # Windows Update error log (System Event Log)
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
        $results.Add($output)
    } catch {
        $results.Add([PSCustomObject]@{
            ComputerName = $job.Computer
            Error = $_.Exception.Message
        })
    }
    $job.Pipe.Dispose()
}

# Save results to CSV
$results | Sort-Object ComputerName | Export-Csv -Path $outputCsv -NoTypeInformation -Encoding UTF8
Write-Host "✅ Report saved to: $outputCsv"
