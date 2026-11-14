#if DOWNLOAD_ISOLATED
using System.Net;
using System.Net.Sockets;
using System.Text;
using FlymeNative.Core;

internal static class DownloadProxyTests
{
    public static async Task RunAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var origin = new TcpListener(IPAddress.Loopback, 0);
        using var downstream = new TcpListener(IPAddress.Loopback, 0);
        origin.Start();
        downstream.Start();
        var originPort = ((IPEndPoint)origin.LocalEndpoint).Port;
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = async (context, token) =>
            {
                Ensure(context.DnsEndPoint.Host == DownloadServer.TargetHost && context.DnsEndPoint.Port == 80, "fixed original upstream authority");
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(IPAddress.Loopback, originPort, token);
                    return new NetworkStream(socket, true);
                }
                catch { socket.Dispose(); throw; }
            }
        };
        using var upstream = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        var originTask = Task.Run(async () =>
        {
            using var socket = await origin.AcceptTcpClientAsync(deadline.Token);
            var stream = socket.GetStream();
            var request = await DownloadRequest.ReadAsync(stream, deadline.Token);
            Ensure(request.Method == "POST" && request.PathAndQuery == "/resource?apk=ignored.apk", "non-APK path and query preserved");
            Ensure(!request.IsApk, "APK query alone does not select payload");
            Ensure(!request.Headers.ContainsKey("X-Remove") && !request.Headers.ContainsKey("Proxy-Authorization"), "request hop headers removed");
            Ensure(request.Headers.GetValueOrDefault("X-Keep") == "kept", "request end-to-end header retained");
            var body = new byte[4];
            await stream.ReadExactlyAsync(body, deadline.Token);
            Ensure(Encoding.ASCII.GetString(body) == "data", "request body streamed");
            await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close, X-Remove\r\nX-Remove: secret\r\nX-Keep: response\r\nSet-Cookie: a=b\r\n\r\n4\r\nbody\r\n3\r\n123\r\n0\r\n\r\n"), deadline.Token);
        }, deadline.Token);
        var proxyTask = Task.Run(async () =>
        {
            using var socket = await downstream.AcceptTcpClientAsync(deadline.Token);
            var stream = socket.GetStream();
            var request = await DownloadRequest.ReadAsync(stream, deadline.Token);
            await DownloadProxy.SendAsync(upstream, stream, request, false, deadline.Token, _ => { });
        }, deadline.Token);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)downstream.LocalEndpoint).Port, deadline.Token);
        await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes($"POST /resource?apk=ignored.apk HTTP/1.1\r\nHost: {DownloadServer.TargetHost}\r\nContent-Length: 4\r\nConnection: close, X-Remove\r\nX-Remove: secret\r\nProxy-Authorization: secret\r\nX-Keep: kept\r\n\r\ndata"), deadline.Token);
        using var output = new MemoryStream();
        await client.GetStream().CopyToAsync(output, deadline.Token);
        var response = Encoding.ASCII.GetString(output.ToArray());
        Ensure(response.StartsWith("HTTP/1.1 200", StringComparison.Ordinal) && response.EndsWith("\r\n\r\nbody123", StringComparison.Ordinal), "real upstream response streamed and dechunked");
        Ensure(!response.Contains("X-Remove", StringComparison.OrdinalIgnoreCase) && !response.Contains("Transfer-Encoding", StringComparison.OrdinalIgnoreCase), "response hop headers removed");
        Ensure(response.Contains("X-Keep: response", StringComparison.OrdinalIgnoreCase) && response.Contains("Set-Cookie: a=b", StringComparison.OrdinalIgnoreCase), "response end-to-end headers retained");
        await Task.WhenAll(originTask, proxyTask);
        Console.WriteLine("PASS: real loopback upstream forwarding, fixed authority, request body, response streaming, hop-header sanitation, non-APK query routing");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("FAILED: " + message);
    }
}
#endif
