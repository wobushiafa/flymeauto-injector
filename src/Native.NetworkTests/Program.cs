using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using FlymeNative.Core;

const string host = "carapp-a-res.flymeauto.com";
var directory = Path.Combine(Path.GetTempPath(), "flyme-network-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
try
{
    var payload = RandomNumberGenerator.GetBytes(262_177);
    var path = Path.Combine(directory, "payload.apk");
    await File.WriteAllBytesAsync(path, payload);
    var logs = new List<string>();
    await using var server = new DownloadServer(path, IPAddress.Loopback, 0, 0, message => { lock (logs) logs.Add(message); });
    await server.StartAsync();
    Check(server.HttpsPort > 0 && server.HttpPort > 0 && server.HttpPort != server.HttpsPort, "actual ephemeral ports");
    try { await server.StartAsync(); throw new Exception("duplicate start accepted"); }
    catch (InvalidOperationException) { }
    using var handler = new HttpClientHandler();
    handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
        cert?.GetNameInfo(X509NameType.DnsName, false) == host &&
        (errors & SslPolicyErrors.RemoteCertificateNotAvailable) == 0;
    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
    await File.WriteAllBytesAsync(path, [0, 1, 2]);
    foreach (var scheme in new[] { "https", "http" })
    {
        var port = scheme == "https" ? server.HttpsPort : server.HttpPort;
        using var request = Request(scheme, port, "/download.APK?version=1");
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.PartialContent, "full transfer 206");
        var actual = await response.Content.ReadAsByteArrayAsync();
        Check(actual.AsSpan().SequenceEqual(payload), "complete immutable snapshot bytes");
        Check(response.Content.Headers.ContentLength == payload.Length, "full content length");
        Check(response.Content.Headers.ContentRange?.ToString() == $"bytes 0-{payload.Length - 1}/{payload.Length}", "full content range");
        Check(response.Headers.ETag?.Tag == $"\"{Convert.ToHexString(MD5.HashData(payload))}\"", "uppercase ETag");
        Check(response.Content.Headers.ContentMD5?.AsSpan().SequenceEqual(MD5.HashData(payload)) == true, "base64 MD5");
        Check(response.Headers.Server.ToString() == "Tengine", "CDN server header");
        Check(response.Headers.ConnectionClose == true, "explicit close framing");
        using var head = Request(scheme, port, "/file.apk");
        head.Method = HttpMethod.Head;
        using var headResponse = await client.SendAsync(head);
        Check(headResponse.StatusCode == HttpStatusCode.PartialContent && headResponse.Content.Headers.ContentLength == payload.Length, "HEAD metadata");
        Check((await headResponse.Content.ReadAsByteArrayAsync()).Length == 0, "HEAD has no body");
    }
    foreach (var (range, start, end) in new (string, int, int)[] { ("bytes=17-99", 17, 99), ("bytes=1024-", 1024, payload.Length - 1), ("bytes=-73", payload.Length - 73, payload.Length - 1), ("bytes=0-999999", 0, payload.Length - 1) })
    {
        using var request = Request("https", server.HttpsPort, "/file.apk");
        request.Headers.TryAddWithoutValidation("Range", range);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.PartialContent, range + " status");
        Check((await response.Content.ReadAsByteArrayAsync()).AsSpan().SequenceEqual(payload.AsSpan(start, end - start + 1)), range + " bytes");
        Check(response.Content.Headers.ContentRange?.ToString() == $"bytes {start}-{end}/{payload.Length}", range + " metadata");
    }
    foreach (var range in new[] { "bytes=999999-", "bytes=10-2", "bytes=-0", "bytes=0-1,3-4", "bytes=abc-", "items=0-2", "bytes=9223372036854775808-" })
    {
        using var request = Request("https", server.HttpsPort, "/file.apk");
        request.Headers.TryAddWithoutValidation("Range", range);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable, range + " rejected");
        Check(response.Content.Headers.ContentRange?.ToString() == $"bytes */{payload.Length}", "416 total length");
    }
    foreach (var wrong in new[] { "evil.example", host + ".evil.example", "prefix-" + host })
    {
        using var request = Request("https", server.HttpsPort, "/file.apk");
        request.Headers.Host = wrong;
        using var response = await client.SendAsync(request);
        Check((int)response.StatusCode == 421, "exact host enforcement");
    }
    using (var request = Request("https", server.HttpsPort, "/file.apk"))
    {
        request.Method = HttpMethod.Post;
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.MethodNotAllowed, "APK methods restricted");
    }
    await CheckTlsAsync(server.HttpsPort);
    await CheckMalformedAsync(server.HttpPort);
    using var stalledTls = new TcpClient();
    await stalledTls.ConnectAsync(IPAddress.Loopback, server.HttpsPort);
    using var stalledHttp = new TcpClient();
    await stalledHttp.ConnectAsync(IPAddress.Loopback, server.HttpPort);
    var httpsPort = server.HttpsPort;
    var httpPort = server.HttpPort;
    await server.StopAsync().WaitAsync(TimeSpan.FromSeconds(5));
    lock (logs)
    {
        Check(logs.Any(line => line.Contains("[TCP到达]", StringComparison.Ordinal)), "TCP acceptance diagnostic emitted");
        Check(logs.Any(line => line.Contains("[TLS开始]", StringComparison.Ordinal)), "TLS start diagnostic emitted");
        Check(logs.Any(line => line.Contains("[TLS成功]", StringComparison.Ordinal)), "TLS success diagnostic emitted");
        Check(logs.Any(line => line.Contains("[HTTP请求]", StringComparison.Ordinal) && line.Contains("Range=bytes=17-99", StringComparison.Ordinal)), "HTTP Range diagnostic emitted");
        Check(logs.Any(line => line.Contains("[HTTP响应] status=206", StringComparison.Ordinal)), "206 response diagnostic emitted");
        Check(logs.Any(line => line.Contains("[APK发送完成]", StringComparison.Ordinal) && line.Contains($"sent={payload.Length}", StringComparison.Ordinal)), "actual body count diagnostic emitted");
        Check(logs.Any(line => line.Contains("[连接失败] stage=TLS握手", StringComparison.Ordinal)), "stalled TLS cancellation stage diagnostic emitted");
    }
    using (var reboundTls = new TcpListener(IPAddress.Loopback, httpsPort)) reboundTls.Start();
    using (var reboundHttp = new TcpListener(IPAddress.Loopback, httpPort)) reboundHttp.Start();
    using (var blocked = new TcpListener(IPAddress.Loopback, 0))
    {
        blocked.Start();
        var blockedPort = ((IPEndPoint)blocked.LocalEndpoint).Port;
        await using var failed = new DownloadServer(path, IPAddress.Loopback, 0, blockedPort);
        try { await failed.StartAsync(); throw new InvalidOperationException("bind failure was accepted"); }
        catch (SocketException) { }
        using var rebound = new TcpListener(IPAddress.Loopback, failed.HttpsPort);
        rebound.Start();
    }
    for (var attempt = 0; attempt < 20; attempt++)
    {
        using var cancellation = new CancellationTokenSource();
        await using var cancelled = new DownloadServer(path, IPAddress.Loopback, 0, 0);
        await cancelled.StartAsync(cancellation.Token);
        using var pending = new TcpClient();
        await pending.ConnectAsync(IPAddress.Loopback, cancelled.HttpPort);
        cancellation.Cancel();
        await cancelled.StopAsync().WaitAsync(TimeSpan.FromSeconds(5));
    }
    await File.WriteAllBytesAsync(path, payload);
    var report = Path.Combine(directory, "receipt.json");
    await DownloadSelfTest.RunAsync(path, report);
    using var receipt = JsonDocument.Parse(await File.ReadAllTextAsync(report));
    Check(receipt.RootElement.GetProperty("hardwareTested").GetBoolean() == false, "receipt hardware honesty");
    Check(receipt.RootElement.GetProperty("sha256").GetString() == Convert.ToHexString(SHA256.HashData(payload)), "receipt full transfer hash");
    Check(logs.Any(line => line.Contains("bytes sent", StringComparison.Ordinal)), "transfer byte logging");
#if DOWNLOAD_ISOLATED
    await DownloadProxyTests.RunAsync();
#endif
    Console.WriteLine("PASS: HTTP/TLS snapshot, full bytes/hash, HEAD, range/resume, 416, exact Host, TLS/ALPN/certificate, malformed headers, shutdown, bind rollback, cancellation, self-test receipt");
}
finally { Directory.Delete(directory, true); }

static HttpRequestMessage Request(string scheme, int port, string path)
{
    var request = new HttpRequestMessage(HttpMethod.Get, $"{scheme}://127.0.0.1:{port}{path}");
    request.Headers.Host = "carapp-a-res.flymeauto.com";
    return request;
}

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException("FAILED: " + message);
}

static async Task CheckTlsAsync(int port)
{
    using var tcp = new TcpClient();
    await tcp.ConnectAsync(IPAddress.Loopback, port);
    using var tls = new SslStream(tcp.GetStream(), false, (_, cert, _, errors) =>
        cert?.Subject == "CN=carapp-a-res.flymeauto.com" && (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0);
    await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
    {
        TargetHost = "carapp-a-res.flymeauto.com",
        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]
    });
    Check(tls.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11, "ALPN http/1.1");
    Check(tls.SslProtocol is SslProtocols.Tls12 or SslProtocols.Tls13, "TLS 1.2/1.3");
}

static async Task CheckMalformedAsync(int port)
{
    foreach (var input in new[]
    {
        "GET /file.apk HTTP/1.1\r\nHost: carapp-a-res.flymeauto.com\r\nHost: evil.example\r\n\r\n",
        "GET /file.apk HTTP/1.1\r\nHost: carapp-a-res.flymeauto.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET /file.apk HTTP/1.1\r\nHost: carapp-a-res.flymeauto.com\r\nX-Long: " + new string('x', 32768) + "\r\n\r\n"
    })
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        await tcp.GetStream().WriteAsync(Encoding.ASCII.GetBytes(input));
        var response = new byte[1024];
        var count = await tcp.GetStream().ReadAsync(response).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Check(Encoding.ASCII.GetString(response, 0, count).StartsWith("HTTP/1.1 4", StringComparison.Ordinal), "malformed request rejected");
    }
}
