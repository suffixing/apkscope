# usage: bench\measure.ps1 <exe> <args...>   -> wall time and peak memory of one process
# plain $args: a param() block would swallow child flags like -d or -cp
$Exe, $Rest = $args
$si = New-Object Diagnostics.ProcessStartInfo $Exe
$si.Arguments = ($Rest | ForEach-Object { '"' + $_ + '"' }) -join ' '
$si.UseShellExecute = $false
$si.RedirectStandardOutput = $true
$si.RedirectStandardError = $true
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = [Diagnostics.Process]::Start($si)
# drain pipes asynchronously so the child never blocks on a full buffer
$out = $p.StandardOutput.ReadToEndAsync(); $err = $p.StandardError.ReadToEndAsync()
$peak = 0
# PeakWorkingSet64 is a running maximum, so polling only has to catch the process before it exits
while (-not $p.HasExited) { $p.Refresh(); try { $peak = [math]::Max($peak, $p.PeakWorkingSet64) } catch {}; Start-Sleep -Milliseconds 2 }
$p.WaitForExit()
"{0:N0} ms, peak {1:N0} MB, exit {2}" -f $sw.ElapsedMilliseconds, ($peak / 1MB), $p.ExitCode
