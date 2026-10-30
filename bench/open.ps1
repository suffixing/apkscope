# usage: bench\open.ps1 <label> <apk-name-in-title> <exe> <args...>
# Launch a GUI with an APK and report two moments:
#   browsable: its window title shows the APK (class tree loaded)
#   idle:      after that, CPU stayed under 3% of one core for 5 s (background work done)
# plus RAM at each moment and peak RAM, then close it. Gives up after 2 hours.
$Label, $Title, $Exe, $Rest = $args
$si = New-Object Diagnostics.ProcessStartInfo $Exe
$si.Arguments = ($Rest | ForEach-Object { '"' + $_ + '"' }) -join ' '
$si.UseShellExecute = $false
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = [Diagnostics.Process]::Start($si)
$browsable = $null; $wsBrowse = 0; $peak = 0; $quietSince = $null; $wsIdle = 0
$lastCpu = 0; $lastT = 0
while ($true) {
  Start-Sleep -Milliseconds 500
  $t = $sw.Elapsed.TotalSeconds
  if ($t -gt 7200) { break }
  $q = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
  if (-not $q) { break }
  $cpu = $q.CPU; $ws = $q.WorkingSet64
  $peak = [math]::Max($peak, $q.PeakWorkingSet64)
  if (-not $browsable -and $q.MainWindowTitle -like "*$Title*") { $browsable = $t; $wsBrowse = $ws }
  $busy = ($cpu - $lastCpu) / [math]::Max($t - $lastT, 0.001)
  $lastCpu = $cpu; $lastT = $t
  if ($browsable -and $busy -lt 0.03) {
    if (-not $quietSince) { $quietSince = $t; $wsIdle = $ws }
    if ($t - $quietSince -ge 5) { break }
  } else { $quietSince = $null }
}
"{0,-10} browsable {1:N1} s ({2:N0} MB) | idle {3:N1} s ({4:N0} MB) | peak {5:N0} MB" -f $Label, $browsable, ($wsBrowse / 1MB), $quietSince, ($wsIdle / 1MB), ($peak / 1MB)
Stop-Process -Id $p.Id -ErrorAction SilentlyContinue
