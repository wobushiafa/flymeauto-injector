# Windows development and release

## Prerequisites

- Windows x64, .NET 10 SDK, PowerShell.
- NativeAOT: Visual Studio 2022 or newer with Desktop development with C++ and a Windows SDK.
- Administrator access is needed for live hotspot/driver tests, not ordinary compilation or loopback tests.
- Optional APK signature verification: Android SDK build-tools `36.1.0`, platform `android-36`, and `ANDROID_HOME`.

Run `scripts/Prepare-Drivers.ps1` before building. It downloads official WinDivert x64 binaries, checks a pinned archive hash and validates the SYS signature. Binaries and dependency caches are ignored by Git.

## Local checks

From `src/`:

```powershell
dotnet build Native.Desktop/Native.Desktop.csproj -c Debug
dotnet run --project Native.RedirectTests/Native.RedirectTests.csproj
dotnet run --file Native.DnsTests/Program.cs
dotnet run --project Native.NetworkTests/Native.NetworkTests.csproj
dotnet build Native.Preview/Native.Preview.csproj -c Release
dotnet Native.Preview/bin/Release/net10.0/win-x64/Native.Preview.dll Native.Preview/previews-local
```

The preview creates its own random download fixture. This verifies GUI input and real loopback HTTPS transport; the fixture is not an installable APK. Generated images, fixtures and receipts are ignored. `Native.ApkTests` separately constructs APK fixtures and uses Android tools to verify signatures; run it with `dotnet run --project Native.ApkTests/Native.ApkTests.csproj`.

No numerical coverage threshold is set. Keep hardware results separate from protocol and GUI tests. `Native.RedirectTests --driver-smoke <report>` requires an elevated process and an active hotspot, briefly opens real interception handles and checks repeated cleanup; it does not prove vehicle installation.

## Build a release

From the repository root:

```powershell
./scripts/Publish-Windows.ps1
```

This uses the standard .NET NativeAOT toolchain. A fallback toolchain can be provisioned from official, hash-pinned Microsoft archives without installing Visual Studio:

```powershell
./scripts/Publish-Windows.ps1 -UseLocalToolchain
# Reuse provisioned tools:
./scripts/Publish-Windows.ps1 -UseLocalToolchain -SkipBootstrap
```

The script rejects an existing package directory to prevent stale files entering a release. Move or delete that specific output directory before rebuilding. Outputs are under root `artifacts/`:

- `flymeauto-injector-<version>-win-x64/`: complete runtime directory and third-party notices.
- `flymeauto-injector-<version>-win-x64.zip` and `.zip.sha256`: distributable downloads.
- `*-verification.json`: checks the PE is AMD64 NativeAOT with the administrator manifest.

The package includes no test APK, private key, raw capture, toolchain, debug symbols or .NET SDK. Do not remove runtime DLL/SYS files. Published application binaries are not code-signed; enterprise execution policies may require administrator-managed approval.

## GitHub

`.github/workflows/windows.yml` runs DNS/connection/HTTP/TLS checks and GUI previews, then publishes on a Windows runner with its C++ toolchain. Tagged builds additionally create a GitHub Release. The release job uses Linux only to upload files; the distributed program is Windows x64 only.

1. Update `Version` in `src/Native.Desktop/Native.Desktop.csproj` and the window title as appropriate.
2. Commit, push, and verify CI.
3. Push a matching tag, such as `v1.1.0`. A mismatched tag fails validation.
4. Check the Release ZIP, hash file and release notes. The workflow uses the built-in GitHub token with write access limited to the release job.

Live acceptance: start the packaged program, choose an APK and exact target size, reconnect the vehicle hotspot, create a fresh download, verify installation and launch, then stop and confirm resources are released. Do not equate loopback success or socket byte counts with successful installation.

## Repository hygiene

Commit source, documentation, fixtures containing no personal data and dependency license notices. Do not commit `artifacts/`, `bin/`, `obj/`, APK files, signing identities, network captures or machine-specific diagnostics. Internal `FlymeNative` namespaces and the local data directory are retained for compatibility; the executable and release package use `flymeauto-injector`.

Before making the repository public, choose an explicit license for your own source. Third-party licenses do not grant a license to this repository's original code.
