# Architecture

The Windows x64 application uses .NET 10, C# 14, Avalonia and NativeAOT.

## Replacement session

1. Discover exactly one active Wi-Fi Direct IPv4 hotspot and resolve the download domain to a public IPv4.
2. Prepare an exact-size APK with v1/v2 signing, and start the local HTTP/TLS download server.
3. Open WinDivert forward/return handles; authorize each hotspot client before answering its target DNS query.
4. Admit only new SYN packets for that client, session CDN and port 80/443. Translate destinations to the local server and return sources to the public address.
5. Expire idle authorization and flow state. Native WinDivert helpers recalculate checksums after address changes.

`DownloadRouteTable` owns connection state. Existing connections are not forcibly
captured; system routes are not changed. Scope is IPv4 UDP DNS and TCP 80/443.

## Lifecycle

`SessionController` serializes startup and rollback. Stop ends DNS interception,
closes downloads, releases translation handles, then removes this session's
firewall rule and temporary APK. Observation and original-query controls are
separate from replacement mode.

`SessionLog` writes full logs. Optional `NicCapture` owns only the PktMon session
it started, records the full network stack for at most 60 seconds and exports
diagnostics without taking over an existing capture.

The desktop uses a bounded grid. Its 160-pixel read-only log TextBox wraps text
and owns its vertical scrollbar; the window has no outer ScrollViewer.

## Validation

Protocol tests cover malformed packets, real TLS, bytes/hash, Range, connection
isolation and expiry. Previews exercise actual Avalonia controls and loopback
HTTPS. Driver smoke checks real handle lifecycle. Vehicle acceptance must verify
download, installation and launch separately. A successful experiment on one
vehicle does not guarantee every firmware or store entry behaves identically.
