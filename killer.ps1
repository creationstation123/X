$processNameToKill = "ccSVCHst.exe"

while ($true) {
    # Check if the process is running
    if (Test-ProcessRunning -ProcessName $processNameToKill) {
        # If it's running, try to terminate it
        if (Terminate-Process -ProcessName $processNameToKill) {
            Write-Host "Terminated $processNameToKill."
        } else {
            Write-Host "Failed to terminate $processNameToKill."
        }
    }

    # Sleep for a while before checking again (e.g., every 5 seconds)
    Start-Sleep -Seconds 5
}

function Test-ProcessRunning {
    param (
        [string]$ProcessName
    )

    $runningProcesses = Get-Process | Where-Object { $_.ProcessName -eq $ProcessName }
    return $runningProcesses.Count -gt 0
}

function Terminate-Process {
    param (
        [string]$ProcessName
    )

    try {
        $runningProcesses = Get-Process | Where-Object { $_.ProcessName -eq $ProcessName }
        foreach ($process in $runningProcesses) {
            $process.Kill()
        }
        return $true
    } catch {
        return $false
    }
}
