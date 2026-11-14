# Repository Guidelines

## Project Structure & Module Organization

The Windows desktop application lives in `src/` and uses C# 14, .NET 10, and Avalonia. `Native.Core/` implements APK processing and networking; `Native.Desktop/` contains the UI and session management. Console verification projects include `Native.ApkTests/`, `Native.NetworkTests/`, `Native.Simulation/`, and `Native.ObserverSmoke/`. `Native.Preview/` provides headless UI rendering and GUI checks. `doc/` contains reference Python and shell implementations. `capture/` and `src/verification/` hold diagnostic evidence; `src/toolchain/` supports NativeAOT publishing. Consult `src/DESIGN.md` and `src/PLAN.md` before changing module boundaries.

## Build, Test, and Development Commands

Run these commands from `src/` with the .NET 10 SDK:

- `dotnet build Native.Desktop/Native.Desktop.csproj -c Debug` builds the desktop application.
- `dotnet run --project Native.Desktop/Native.Desktop.csproj -c Debug` launches the UI; its Windows manifest requires administrator privileges.
- `dotnet run --project Native.NetworkTests/Native.NetworkTests.csproj` runs network protocol and download checks.
- `dotnet run --project Native.ApkTests/Native.ApkTests.csproj` validates APK construction and signatures. Set `ANDROID_HOME`; the harness expects build-tools `36.1.0` and platform `android-36`.
- `./Publish.ps1` bootstraps the native toolchain and packages the Windows x64 release. Use `-SkipBootstrap` when the toolchain is already prepared.

## Coding Style & Naming Conventions

Follow existing C# formatting: four-space indentation, file-scoped namespaces, PascalCase types and methods, and camelCase locals and parameters. Keep filenames aligned with their primary types. Nullable references, implicit usings, AOT compatibility, and warnings-as-errors are configured in `src/Directory.Build.props`. Preserve these settings and avoid introducing reflection-dependent code without verifying NativeAOT compatibility. No dedicated formatter or linter configuration was found.

## Testing Guidelines

Tests use executable assertion harnesses rather than a conventional test framework; run them with `dotnet run`. Add checks to the relevant `Native.*Tests` project. No numerical coverage threshold is configured. For UI changes, follow `src/Native.Preview/README.md`, including its APK fixture prerequisite. Report loopback, driver, and physical vehicle validation separately: local success does not establish vehicle compatibility.

## Commit & Pull Request Guidelines

This checkout has no Git metadata, so commit conventions could not be verified. Use concise, imperative commit subjects. PRs should explain the behavior changed, link related issues when available, and record validation commands and results. Include screenshots for UI changes and relevant diagnostic excerpts for network changes. Review captures and logs for sensitive data before sharing them; exclude generated build outputs and downloaded toolchains from source changes.
