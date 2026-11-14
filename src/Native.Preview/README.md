# Desktop preview

Run from `src/`:

```powershell
dotnet build Native.Preview/Native.Preview.csproj -c Release
dotnet Native.Preview/bin/Release/net10.0/win-x64/Native.Preview.dll Native.Preview/previews-local
```

Renders the actual ShellWindow at 1000x760 and 760x650 in light/dark themes.
Screenshots use generic log text to avoid exposing local user paths. Tests check
editable inputs, validation, focus, mode selection and stable controls.

The GUI self-check generates a random 27,233,004-byte transport fixture and
runs the real loopback HTTPS download through the self-check button. The fixture
is not an installable APK. Outputs are ignored by Git. No driver or firewall is
started. See ../../docs/DEVELOPMENT.md for vehicle acceptance boundaries.
