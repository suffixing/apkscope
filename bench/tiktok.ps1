# usage: bench\tiktok.ps1 <apkscope.exe> <app.apk> <work-dir>
# One run each: apkscope export, apkscope decompile-all (output discarded), JADX 1.5.6 Gradle export.
$Exe, $Apk, $Work = $args
$jadx = 'D:\Tools\jadx\lib\jadx-1.5.6-all.jar'
$java = 'D:\Tools\jadx\jre\bin\java.exe'
$m = Join-Path $PSScriptRoot 'measure.ps1'
Remove-Item -Recurse -Force "$Work\apkscope", "$Work\jadx" -ErrorAction SilentlyContinue
"apkscope export:        " + (& $m $Exe export $Apk "$Work\apkscope")
"apkscope decompile all: " + (& $m $Exe decompile $Apk)
"jadx export:            " + (& $m $java -Xmx24g -cp $jadx jadx.cli.JadxCLI -e -d "$Work\jadx" $Apk)
"apkscope files: " + (Get-ChildItem -Recurse -File "$Work\apkscope" | Measure-Object).Count
"jadx files:     " + (Get-ChildItem -Recurse -File "$Work\jadx" | Measure-Object).Count
