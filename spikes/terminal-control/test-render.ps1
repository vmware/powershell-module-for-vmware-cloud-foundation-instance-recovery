<#
    Shared test script for comparing the two terminal-rendering spikes
    (EasyTerminalSpike vs VtNetCoreSpike) against identical output.
    Run this inside each spike's embedded pwsh session.
#>

Write-Host "=== Color test ===" -ForegroundColor Cyan
Write-Host "Red foreground"     -ForegroundColor Red
Write-Host "Green foreground"   -ForegroundColor Green
Write-Host "Yellow on DarkBlue" -ForegroundColor Yellow -BackgroundColor DarkBlue
Write-Host ""

Write-Host "=== Table test ===" -ForegroundColor Cyan
[PSCustomObject]@{ Host = 'esxi-01.lab'; Status = 'Connected'; Cluster = 'mgmt-01' },
[PSCustomObject]@{ Host = 'esxi-02.lab'; Status = 'Maintenance'; Cluster = 'mgmt-01' },
[PSCustomObject]@{ Host = 'esxi-03.lab'; Status = 'Connected'; Cluster = 'wld-01' } |
    Format-Table -AutoSize
Write-Host ""

Write-Host "=== Write-Progress test (in-place update, not scrolling) ===" -ForegroundColor Cyan
for ($i = 0; $i -le 100; $i += 5) {
    Write-Progress -Activity "Rebuilding vSAN datastore" -Status "$i% complete" -PercentComplete $i
    Start-Sleep -Milliseconds 80
}
Write-Progress -Activity "Rebuilding vSAN datastore" -Completed
Write-Host ""

Write-Host "=== Read-Host / confirmation prompt test ===" -ForegroundColor Cyan
$nics = Read-Host "Enter comma-separated NIC IDs (e.g. vmnic2,vmnic3)"
Write-Host "You entered: $nics" -ForegroundColor Green

$confirm = Read-Host "Proceed with rebuild? (Y/N)"
if ($confirm -match '^[Yy]') {
    Write-Host "Confirmed." -ForegroundColor Green
} else {
    Write-Host "Cancelled." -ForegroundColor Yellow
}
