using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Text;
using System.Text.Json;
using System.IO.Compression;
using FlymeNative.Core;

string report = Path.GetFullPath(args.Single());
var lines = new ConcurrentQueue<string>();
var observed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var helloObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
try
{
    string captureDirectory = Path.Combine(Path.GetDirectoryName(report)!, "session-nic-smoke-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(captureDirectory);
    using var sharedLog = new StreamWriter(new FileStream(Path.Combine(captureDirectory, "session.log"), FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
    await sharedLog.WriteLineAsync("Real capture smoke session log; file remains open while the archive is created.");
    await using var nic = new NicCapture(captureDirectory, lines.Enqueue);
    await nic.StartAsync();
    using var observer = new TrafficObserver(new HotspotInfo(1, "loopback-only-smoke", IPAddress.Loopback, 8), line =>
    {
        lines.Enqueue(line);
        if (line.Contains("[WFP观察]", StringComparison.Ordinal) && line.Contains("DNS ", StringComparison.Ordinal)) observed.TrySetResult();
        if (line.Contains("[TLS域名]", StringComparison.Ordinal) && line.Contains("SNI=" + DownloadServer.TargetHost, StringComparison.Ordinal)) helloObserved.TrySetResult();
    });
    observer.Start();
    using var sender = new UdpClient(AddressFamily.InterNetwork);
    var query = new List<byte> { 0x66, 0x77, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    foreach (string label in DownloadServer.TargetHost.Split('.'))
    {
        query.Add((byte)label.Length);
        query.AddRange(Encoding.ASCII.GetBytes(label));
    }
    query.AddRange([0, 0, 1, 0, 1]);
    await sender.SendAsync(query.ToArray(), new IPEndPoint(IPAddress.Loopback, 53));
    await observed.Task.WaitAsync(TimeSpan.FromSeconds(10));
    string payloadPath = Path.Combine(Path.GetTempPath(), "flyme-observer-" + Guid.NewGuid().ToString("N") + ".apk");
    await File.WriteAllBytesAsync(payloadPath, [1, 2, 3]);
    try
    {
        await using var server = new DownloadServer(payloadPath, IPAddress.Loopback, 443, 0);
        await server.StartAsync();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, 443);
        using var tls = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync(DownloadServer.TargetHost);
        await helloObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
    }
    finally { File.Delete(payloadPath); }
    observer.CheckHealth();
    observer.Dispose();
    await nic.StopAsync();
    using (var archive = ZipFile.OpenRead(captureDirectory + "-diagnostics.zip"))
    {
        var pcap = archive.Entries.Single(entry => entry.FullName.EndsWith(".pcapng", StringComparison.Ordinal));
        using var packetStream = pcap.Open();
        byte[] magic = new byte[4];
        packetStream.ReadExactly(magic);
        if (!magic.AsSpan().SequenceEqual(new byte[] { 0x0a, 0x0d, 0x0d, 0x0a }))
            throw new InvalidDataException("Exported archive does not contain pcapng bytes.");
        if (!archive.Entries.Any(entry => entry.FullName.EndsWith(".etl", StringComparison.Ordinal)))
            throw new InvalidDataException("Raw NIC ETL missing from diagnostics archive.");
        if (archive.GetEntry("session.log")?.Length is not > 0)
            throw new InvalidDataException("Open session log was not included in diagnostics archive.");
    }
    using var memory = new MemoryStream();
    using (var json = new Utf8JsonWriter(memory, new JsonWriterOptions { Indented = true }))
    {
        json.WriteStartObject();
        json.WriteBoolean("success", true);
        json.WriteBoolean("liveDriverObserverTested", true);
        json.WriteBoolean("hotspotOrCarTested", false);
        json.WriteStartArray("logs");
        foreach (string line in lines) json.WriteStringValue(line);
        json.WriteEndArray(); json.WriteEndObject();
    }
    await File.WriteAllBytesAsync(report, memory.ToArray());
    return 0;
}
catch (Exception error)
{
    await File.WriteAllTextAsync(report, "FAILED\n" + error + "\n" + string.Join('\n', lines));
    return 1;
}
