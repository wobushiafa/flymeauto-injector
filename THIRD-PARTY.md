# Third-party components

The application runs on Windows x64. Its runtime does not launch Python, Java,
PowerShell or mitmproxy. Windows `netsh` and `pktmon` are used for scoped firewall
rules and optional diagnostics.

| Component | Purpose | License / source |
| --- | --- | --- |
| Avalonia 11.3.22 | Desktop controls and rendering integration | [MIT](https://github.com/AvaloniaUI/Avalonia/blob/master/licence.md) |
| SkiaSharp / Skia | Native graphics | [SkiaSharp licenses](https://github.com/mono/SkiaSharp/tree/main/LICENSE), [Skia BSD](https://skia.googlesource.com/skia/+/main/LICENSE) |
| HarfBuzzSharp / HarfBuzz | Text shaping | [MIT-style license](https://github.com/harfbuzz/harfbuzz/blob/main/COPYING) |
| ANGLE | Windows graphics compatibility | [BSD-style license](docs/licenses/ANGLE.LICENSE) |
| .NET 10 NativeAOT | Native compilation and runtime support | [MIT and third-party notices](https://github.com/dotnet/runtime) |
| WinDivert 2.2.2 | Packet interception library and signed Windows driver | [LGPLv3 or GPLv2](https://github.com/basil00/WinDivert/blob/master/LICENSE) |

## WinDivert redistribution

The source tree and release packages include the available component license
texts and .NET/Skia third-party notices under `docs/licenses/`.

`scripts/Prepare-Drivers.ps1` downloads the official `WinDivert-2.2.2-A.zip`
release, verifies its pinned SHA-256 and the driver signature, and copies only
the x64 DLL and SYS required by the application. The official `WinDivert.dll`
is named `WinDivert64.dll` in the application directory to match its P/Invoke
library name; its contents are unchanged. These are dynamically loaded files.
Do not remove or combine them into the executable.

Release packages include the upstream license and README under
`licenses/WinDivert/`. Corresponding upstream source and build instructions are
available at <https://github.com/basil00/WinDivert/tree/v2.2.2>.
No PyDivert Python binding is used or distributed.

Android SDK `aapt2` / `apksigner` are optional development verification tools;
they are not included in the application package. Microsoft C++ and Windows
SDK tools are build dependencies, not application runtime files.
