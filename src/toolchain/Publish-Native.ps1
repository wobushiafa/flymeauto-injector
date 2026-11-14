param(
    [string]$Project = (Join-Path $PSScriptRoot 'probe\HelloWorld.csproj'),
    [string]$OutputDirectory,
    [switch]$SkipBootstrap
)
$ErrorActionPreference = 'Stop'
if (!$SkipBootstrap) { & (Join-Path $PSScriptRoot 'Bootstrap.ps1') }
$projectPath = (Resolve-Path -LiteralPath $Project).Path
$arguments = @(
    'publish', $projectPath, '-c', 'Release', '-r', 'win-x64',
    '-p:PublishAot=true',
    "-p:CustomAfterMicrosoftCommonTargets=$(Join-Path $PSScriptRoot 'NativeToolchain.targets')"
)
if ($OutputDirectory) {
    $arguments += @('-o', [System.IO.Path]::GetFullPath($OutputDirectory, $PWD.Path))
}
# Select the parent's pinned .NET 10 SDK even when called from another folder.
Push-Location $PSScriptRoot
try {
    & dotnet @arguments
    if ($LASTEXITCODE -ne 0) { throw "NativeAOT publish failed: exit $LASTEXITCODE" }
}
finally { Pop-Location }
