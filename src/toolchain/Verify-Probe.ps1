param([switch]$SkipBootstrap)
$ErrorActionPreference = 'Stop'
$evidence = Join-Path $PSScriptRoot 'evidence'
[System.IO.Directory]::CreateDirectory($evidence) | Out-Null
$publish = Join-Path $evidence 'publish'
& (Join-Path $PSScriptRoot 'Publish-Native.ps1') -OutputDirectory $publish -SkipBootstrap:$SkipBootstrap |
    Tee-Object -FilePath (Join-Path $evidence 'publish.log')

$executable = Join-Path $publish 'HelloWorld.exe'
$output = & $executable
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0 -or $output -notcontains 'Hello from .NET 10 NativeAOT!' -or
    $output -notcontains 'Dynamic code supported: False') {
    throw "Native probe failed: exit $exitCode; output: $output"
}

# PE32+ COFF machine and COM descriptor are independent of MSBuild properties.
$stream = [System.IO.File]::OpenRead($executable)
$reader = [System.IO.BinaryReader]::new($stream)
try {
    if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Missing DOS signature' }
    $stream.Position = 0x3C
    $peOffset = $reader.ReadInt32()
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x4550) { throw 'Missing PE signature' }
    $machine = $reader.ReadUInt16()
    $stream.Position = $peOffset + 24
    $magic = $reader.ReadUInt16()
    if ($machine -ne 0x8664 -or $magic -ne 0x20B) { throw 'Expected x64 PE32+' }
    $stream.Position = $peOffset + 24 + 112 + (14 * 8)
    $clrRva = $reader.ReadUInt32()
    $clrSize = $reader.ReadUInt32()
    if ($clrRva -ne 0 -or $clrSize -ne 0) { throw 'Unexpected CLR header' }
}
finally { $reader.Dispose() }

$result = [ordered]@{
    Executable = $executable
    Sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
    Bytes = (Get-Item -LiteralPath $executable).Length
    Machine = 'AMD64 (0x8664)'
    Format = 'PE32+ (0x20B)'
    ClrHeaderRva = $clrRva
    ClrHeaderSize = $clrSize
    ExitCode = $exitCode
    Output = $output
    VerifiedAtUtc = [DateTime]::UtcNow.ToString('O')
}
$result | ConvertTo-Json | Tee-Object -FilePath (Join-Path $evidence 'result.json')
