[CmdletBinding()]
param(
    [string]$Version = '',
    [switch]$UseLocalToolchain,
    [switch]$SkipBootstrap
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$project = Join-Path $workspace 'src/Native.Desktop/Native.Desktop.csproj'
if (!$Version) { $Version = ([xml](Get-Content -LiteralPath $project -Raw)).Project.PropertyGroup.Version }
if ($Version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') { throw 'Use a semantic version such as 1.1.0.' }
& (Join-Path $PSScriptRoot 'Prepare-Drivers.ps1')
$packageName = "flymeauto-injector-$Version-win-x64"
$artifacts = Join-Path $workspace 'artifacts'
$package = Join-Path $artifacts $packageName
# Publish to a fresh directory so stale runtime files cannot enter the package.
if (Test-Path -LiteralPath $package) { throw "$package already exists. Move or delete the previous package before rebuilding." }
if ($UseLocalToolchain) {
    if (!$SkipBootstrap) { & (Join-Path $workspace 'src/toolchain/Bootstrap.ps1') }
    $targets = Join-Path $workspace 'src/toolchain/NativeToolchain.targets'
    & dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishAot=true "-p:Version=$Version" "-p:CustomAfterMicrosoftCommonTargets=$targets" -o $package
} else {
    & dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishAot=true "-p:Version=$Version" -o $package
}
if ($LASTEXITCODE -ne 0) { throw 'Windows NativeAOT publish failed.' }
$verification = Join-Path $artifacts "$packageName-verification.json"
& (Join-Path $PSScriptRoot 'Inspect-Release.ps1') -Executable (Join-Path $package 'flymeauto-injector.exe') -Report $verification
foreach ($name in @('README.md', 'THIRD-PARTY.md')) { Copy-Item -LiteralPath (Join-Path $workspace $name) -Destination $package }
Copy-Item -LiteralPath (Join-Path $workspace 'docs') -Destination $package -Recurse
if (Test-Path -LiteralPath (Join-Path $workspace 'LICENSE')) { Copy-Item -LiteralPath (Join-Path $workspace 'LICENSE') -Destination $package }
$licenses = Join-Path $package 'licenses/WinDivert'
New-Item -ItemType Directory -Path $licenses -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $workspace 'src/drivers/LICENSE') -Destination $licenses
$officialReadme = Join-Path $artifacts 'dependencies/windivert/WinDivert-2.2.2-A/README'
Copy-Item -LiteralPath $officialReadme -Destination $licenses
# Debug symbols remain a local build output; users only need runtime files.
Get-ChildItem -LiteralPath $package -Filter '*.pdb' -File | Remove-Item
$files = @(Get-ChildItem -LiteralPath $package -File -Recurse | ForEach-Object {
    [ordered]@{ file = $_.FullName.Substring($package.Length + 1).Replace('\', '/'); bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
ConvertTo-Json -InputObject $files -Depth 4 | Set-Content (Join-Path $package 'manifest.json') -Encoding utf8
$zip = Join-Path $artifacts "$packageName.zip"
Compress-Archive -LiteralPath $package -DestinationPath $zip -Force
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $packageName.zip" | Set-Content (Join-Path $artifacts "$packageName.zip.sha256") -Encoding ascii
Write-Output "Windows release: $zip"
