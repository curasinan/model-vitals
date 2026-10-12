param(
    [Parameter(Mandatory = $true)][string]$PythonW,
    [string]$TaskName = "model-vitals",
    [string]$LegacyTaskName = "claude-vitals"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $PythonW)) {
    throw "interpreter not found: $PythonW"
}

$action = New-ScheduledTaskAction -Execute $PythonW -Argument "-m vitals serve"

$logon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$repeat = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 2) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$trigger = @($logon, $repeat)

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 0)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

if ($LegacyTaskName -and $LegacyTaskName -ne $TaskName -and
    (Get-ScheduledTask -TaskName $LegacyTaskName -ErrorAction SilentlyContinue)) {
    Write-Host "removing legacy task '$LegacyTaskName'"
    Stop-ScheduledTask -TaskName $LegacyTaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $LegacyTaskName -Confirm:$false
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "replacing existing task '$TaskName'"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Description "model-vitals telemetry daemon" | Out-Null

Write-Host "registered '$TaskName' -> $PythonW -m vitals serve"
Write-Host "start it now with:  Start-ScheduledTask -TaskName $TaskName"
Write-Host "remove it with:     Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
