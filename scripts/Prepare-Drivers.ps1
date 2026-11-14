[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$cache = Join-Path $workspace 'artifacts/dependencies'
$archive = Join-Path $cache 'WinDivert-2.2.2-A.zip'
$expected = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'
New-Item -ItemType Directory -Path $cache -Force | Out-Null
if (!(Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw "WinDivert archive hash mismatch. Remove $archive and retry."
}
Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $cache 'windivert') -Force
$source = Join-Path $cache 'windivert/WinDivert-2.2.2-A'
$drivers = Join-Path $workspace 'src/drivers'
New-Item -ItemType Directory -Path $drivers -Force | Out-Null
if ((Get-AuthenticodeSignature (Join-Path $source 'x64/WinDivert64.sys')).Status -ne 'Valid') {
    throw 'WinDivert driver signature could not be verified.'
}
Copy-Item -LiteralPath (Join-Path $source 'x64/WinDivert.dll') -Destination (Join-Path $drivers 'WinDivert64.dll') -Force
Copy-Item -LiteralPath (Join-Path $source 'x64/WinDivert64.sys') -Destination (Join-Path $drivers 'WinDivert64.sys') -Force
Copy-Item -LiteralPath (Join-Path $source 'LICENSE') -Destination (Join-Path $drivers 'LICENSE') -Force
Write-Output 'Prepared official WinDivert 2.2.2 x64 binaries; archive SHA-256 and driver signature verified.'
