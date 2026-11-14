param([string]$Package)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$cache = Join-Path $PSScriptRoot 'downloads'
$packages = Join-Path $PSScriptRoot 'packages'
[System.IO.Directory]::CreateDirectory($cache) | Out-Null
[System.IO.Directory]::CreateDirectory($packages) | Out-Null

# ZIP extraction only: no Visual Studio installer, registration, or elevation.
$payloads = @(
    @{
        Name = 'msvc-crt-store-14.44.35226'
        Url = 'https://download.visualstudio.microsoft.com/download/pr/67cf767c-5e71-47c2-a54a-cd5631e28942/9135b03c0df53c7a0aa9bef7230a1c2ff4263a0ee7baa7e419d034f484f6bb56/Microsoft.VC.14.44.17.14.CRT.x64.Store.base.vsix'
        Sha256 = '9135b03c0df53c7a0aa9bef7230a1c2ff4263a0ee7baa7e419d034f484f6bb56'
    },
    @{
        Name = 'msvc-crt-14.44.35226'
        Url = 'https://download.visualstudio.microsoft.com/download/pr/67cf767c-5e71-47c2-a54a-cd5631e28942/f01f701a7bcd9587a340898c851424f6a52bb913a70c185ff0d5bf0288c5831a/Microsoft.VC.14.44.17.14.CRT.x64.Desktop.base.vsix'
        Sha256 = 'f01f701a7bcd9587a340898c851424f6a52bb913a70c185ff0d5bf0288c5831a'
    },
    @{
        Name = 'msvc-tools-14.44.35229'
        Url = 'https://download.visualstudio.microsoft.com/download/pr/aa209763-134c-427b-9960-9ca54ccc1734/f4ad3cee4ef18e9f36382399261de27be6910ab3467178d7e687377ec841306d/Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX64.base.vsix'
        Sha256 = 'f4ad3cee4ef18e9f36382399261de27be6910ab3467178d7e687377ec841306d'
    },
    @{
        Name = 'windows-sdk-x64-10.0.26100.3916'
        Url = 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.x64/10.0.26100.3916/microsoft.windows.sdk.cpp.x64.10.0.26100.3916.nupkg'
        Sha256 = 'ce31d6d47c1333c79501814538ad5f9dbdfb78ac0123fb0ec7978fccbc6a7e82'
    }
)
foreach ($payload in $payloads) {
    if ($Package -and $payload.Name -ne $Package) { continue }
    $archive = Join-Path $cache ($payload.Name + '.zip')
    $destination = Join-Path $packages $payload.Name
    if ((Test-Path -LiteralPath $archive) -and $payload.Sha256 -and
        (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $payload.Sha256) {
        Remove-Item -LiteralPath $archive
    }
    if (!(Test-Path -LiteralPath $archive)) {
        Write-Output "Downloading $($payload.Name)"
        Invoke-WebRequest -Uri $payload.Url -OutFile ($archive + '.partial') -TimeoutSec 600
        Move-Item -LiteralPath ($archive + '.partial') -Destination $archive
    }
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($payload.Sha256 -and $hash -ne $payload.Sha256) {
        throw "SHA256 mismatch: $archive"
    }
    if (!(Test-Path -LiteralPath $destination)) {
        Expand-Archive -LiteralPath $archive -DestinationPath $destination
    }
    Write-Output "$($payload.Name) SHA256 $hash"
}
