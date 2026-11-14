param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$Report
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ReleaseResources {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryEx(string name, IntPtr file, uint flags);
    [DllImport("kernel32.dll", EntryPoint="FindResourceW", SetLastError=true)]
    public static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LockResource(IntPtr resource);
    [DllImport("kernel32.dll")]
    [return:MarshalAs(UnmanagedType.Bool)]
    public static extern bool FreeLibrary(IntPtr module);
}
'@
$path = (Resolve-Path -LiteralPath $Executable).Path
$module = [ReleaseResources]::LoadLibraryEx($path, [IntPtr]::Zero, 0x22)
if ($module -eq [IntPtr]::Zero) { throw 'Cannot load executable resources as data.' }
try {
    $resource = [ReleaseResources]::FindResource($module, [IntPtr]1, [IntPtr]24)
    if ($resource -eq [IntPtr]::Zero) { throw 'Executable manifest resource is missing.' }
    $length = [ReleaseResources]::SizeofResource($module, $resource)
    $memory = [ReleaseResources]::LockResource([ReleaseResources]::LoadResource($module, $resource))
    if ($memory -eq [IntPtr]::Zero -or $length -eq 0) { throw 'Cannot read executable manifest.' }
    $manifestBytes = [byte[]]::new($length)
    [Runtime.InteropServices.Marshal]::Copy($memory, $manifestBytes, 0, $manifestBytes.Length)
    [xml]$manifest = [Text.Encoding]::UTF8.GetString($manifestBytes).Trim([char]0)
    $privilege = $manifest.SelectSingleNode("//*[local-name()='requestedExecutionLevel']")
    if ($privilege.level -ne 'requireAdministrator') { throw "Expected requireAdministrator, got $($privilege.level)." }
} finally {
    if (-not [ReleaseResources]::FreeLibrary($module)) { throw 'Cannot release resource handle.' }
}
$bytes = [IO.File]::ReadAllBytes($path)
$pe = [BitConverter]::ToInt32($bytes, 0x3c)
if ([BitConverter]::ToUInt32($bytes, $pe) -ne 0x4550) { throw 'Missing PE signature.' }
$machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
$optional = $pe + 24
if ($machine -ne 0x8664 -or [BitConverter]::ToUInt16($bytes, $optional) -ne 0x20b) { throw 'Expected AMD64 PE32+.' }
$clr = $optional + 112 + 14 * 8
if ([BitConverter]::ToUInt64($bytes, $clr) -ne 0) { throw 'Unexpected CLR directory: artifact is not the required native PE.' }
$result = [ordered]@{
    success = $true
    executable = $path
    sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    requestedExecutionLevel = [string]$privilege.level
    machine = 'AMD64'
    clrDirectoryRva = 0
    clrDirectorySize = 0
}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($Report), ($result | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
$result | ConvertTo-Json
