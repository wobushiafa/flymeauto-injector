# Optional local NativeAOT toolchain

From the repository root, run `./scripts/Publish-Windows.ps1 -UseLocalToolchain`.
This downloads official Microsoft archives, verifies pinned SHA-256 hashes and
extracts tools into ignored directories. No installer runs or SDK files change.
Use `-SkipBootstrap` only after the tools have been fully provisioned.

The .NET 10 SDK is required. The normal GitHub workflow uses the runner's
Visual Studio C++ toolchain instead of this fallback.

| Input | Version |
| --- | --- |
| MSVC x64 tools | 14.44.35229 |
| MSVC Desktop / Store CRT | 14.44.35226 |
| Windows SDK x64 libraries | 10.0.26100.3916 |

Microsoft licenses remain in the cached archives. Do not distribute build tools
with the application. If an extracted package is incomplete, remove that specific
package directory before running bootstrap again. See ../../docs/DEVELOPMENT.md.
