# usage: bench\asc.ps1 <rust_ASC.exe> <apkscope.exe> [runs]
# Same queries through rust_ASC and apkscope's stateless commands; median wall time and peak
# memory of `runs` runs each, as a Markdown table. APKs and classes are listed below.
param([string]$Asc, [string]$Ours, [int]$Runs = 5)

$apks = @(
    @{ name = "Zestle";  path = "D:\apks\Zestle_v0.6.8-prealpha.apk"; class = "com.google.gson.Gson" },
    @{ name = "Unciv";   path = "D:\apks\Unciv.apk";                  class = "com.unciv.UncivGame" },
    @{ name = "Capital"; path = "D:\apks\base.apk";                   class = "okhttp3.OkHttpClient" },
    @{ name = "TikTok";  path = "D:\APKS\tiktok-47-2-41.apk";         class = "com.ss.android.ugc.aweme.app.api.RequestLog" },
    # F-Droid builds, https://f-droid.org/repo/<file>
    @{ name = "KeePassDX";   path = "D:\apks\fdroid\com.kunzisoft.keepass.libre_45600.apk";  class = "com.kunzisoft.keepass.activities.stylish.StylishActivity" },
    @{ name = "Nextcloud";   path = "D:\apks\fdroid\com.nextcloud.client_350000190.apk";     class = "com.nextcloud.client.device.PowerManagementService" },
    @{ name = "AntennaPod";  path = "D:\apks\fdroid\de.danoeh.antennapod_3120395.apk";       class = "de.danoeh.antennapod.activity.MainActivity" },
    @{ name = "Element";     path = "D:\apks\fdroid\im.vector.app_40106624.apk";             class = "im.vector.app.Hilt_VectorApplication" },
    @{ name = "OsmAnd";      path = "D:\apks\fdroid\net.osmand.plus_541003.apk";             class = "net.osmand.plus.routing.RouteService" },
    @{ name = "Thunderbird"; path = "D:\apks\fdroid\net.thunderbird.android_33.apk";         class = "net.thunderbird.app.common.MainActivity" },
    @{ name = "Fennec";      path = "D:\apks\fdroid\org.mozilla.fennec_fdroid_1580220.apk";  class = "org.mozilla.fenix.FenixApplication" },
    @{ name = "NewPipe";     path = "D:\apks\fdroid\org.schabi.newpipe_1015.apk";            class = "org.schabi.newpipe.ExitActivity" },
    @{ name = "VLC";         path = "D:\apks\fdroid\org.videolan.vlc_13070208.apk";          class = "org.videolan.vlc.IDebugLogService" },
    @{ name = "Wikipedia";   path = "D:\apks\fdroid\org.wikipedia_50614.apk";                class = "org.wikipedia.activity.BaseActivity" }
)

function Measure-Run($exe, [string[]]$argv) {
    $si = New-Object Diagnostics.ProcessStartInfo $exe
    $si.Arguments = ($argv | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $si.UseShellExecute = $false
    $si.RedirectStandardOutput = $true
    $si.RedirectStandardError = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($si)
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    $peak = 0
    while (-not $p.HasExited) { $p.Refresh(); try { $peak = [math]::Max($peak, $p.PeakWorkingSet64) } catch {}; Start-Sleep -Milliseconds 1 }
    $p.WaitForExit()
    $ms = $sw.ElapsedMilliseconds
    $lines = ($o.Result -split "`n").Count
    @{ ms = $ms; mb = [math]::Round($peak / 1MB); exit = $p.ExitCode; lines = $lines }
}

function Median($exe, [string[]]$argv) {
    $r = 1..$Runs | ForEach-Object { Measure-Run $exe $argv }
    $sorted = $r | Sort-Object { $_.ms }
    $m = $sorted[[int][math]::Floor($Runs / 2)]
    $m.mb = ($r | ForEach-Object { $_.mb } | Measure-Object -Maximum).Maximum
    $m
}

"| APK | Query | rust_ASC | apkscope | Speed-up |"
"|---|---|---:|---:|---:|"
foreach ($a in $apks) {
    $p = $a.path
    $tests = @(
        @("String xref ``https://``", @("findrefs", $p, "string", "https://"), @("refs", $p, "string", "https://")),
        @("Method xref ``openConnection``", @("findrefs", $p, "method", "openConnection"), @("refs", $p, "method", "openConnection")),
        @("Decompile one class", @("getclass", $p, $a.class), @("decompile", $p, $a.class)),
        @("List classes", @("listclass", $p), @("classes", $p)),
        @("List methods", @("listmethod", $p), @("methods", $p)),
        @("List strings ``-f http``", @("liststring", "-f", "http", $p), @("strings", $p, "--filter", "http")),
        @("Decode manifest", @("getmanifest", $p), @("manifest", $p))
    )
    foreach ($t in $tests) {
        $x = Median $Asc $t[1]
        $y = Median $Ours $t[2]
        $ratio = if ($y.ms -gt 0) { "{0:N1}x" -f ($x.ms / $y.ms) } else { "-" }
        $xs = if ($x.exit -eq 0) { "{0:N0} ms / {1:N0} MB" -f $x.ms, $x.mb } else { "failed (exit {0})" -f $x.exit }
        $ys = if ($y.exit -eq 0) { "{0:N0} ms / {1:N0} MB" -f $y.ms, $y.mb } else { "failed (exit {0})" -f $y.exit }
        "| $($a.name) | $($t[0]) | $xs | $ys | $ratio |"
    }
}
