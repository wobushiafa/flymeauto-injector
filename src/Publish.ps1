param([switch]$UseLocalToolchain, [switch]$SkipBootstrap)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '../scripts/Publish-Windows.ps1') -UseLocalToolchain:$UseLocalToolchain -SkipBootstrap:$SkipBootstrap
