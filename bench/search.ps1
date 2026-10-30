# usage: bench\search.ps1 <apkscope.exe> <app.apk>
# Time and peak RAM of each search, as a fresh process (load + index + search). The cache for
# this APK is cleared first, so the first code search is cold and the second one warm.
$Exe, $Apk = $args
$m = Join-Path $PSScriptRoot 'measure.ps1'
Remove-Item -Recurse -Force (Join-Path $env:LOCALAPPDATA 'apkscope\cache') -ErrorAction SilentlyContinue
$runs = @(
  @('string "/api/"', @('string', '/api/')),
  @('urls (all)',     @('urls')),
  @('secrets (all)',  @('secrets')),
  @('http (all)',     @('http')),
  @('usages addHeader', @('usages', 'addHeader')),
  @('code "api/auth" (cold)', @('code', 'api/auth')),
  @('code "api/auth" (warm)', @('code', 'api/auth'))
)
foreach ($r in $runs) {
  $label, $a = $r
  $args2 = @('search', $Apk) + $a + @('--out', "$env:TEMP\apkscope-bench.txt")
  "{0,-26} {1}" -f $label, (& $m $Exe @args2)
}
