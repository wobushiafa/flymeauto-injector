using System.Buffers.Binary;
using System.Net;
using FlymeNative.Core;

if (args is ["--driver-smoke", var report])
{
    var evidence = new List<string>();
    var actualHotspot = WindowsNetwork.DiscoverHotspot();
    var actualCdn = await DownloadRedirector.ResolveAddressAsync(CancellationToken.None);
    for (int iteration = 0; iteration < 3; iteration++)
    {
        using var redirect = new DownloadRedirector(actualHotspot, actualCdn, evidence.Add);
        redirect.Start();
        using var interceptor = new DnsInterceptor(actualHotspot, evidence.Add, downloadAddress: actualCdn, answered: redirect.AuthorizeClient);
        interceptor.Start();
        interceptor.CheckHealth(); redirect.CheckHealth();
        interceptor.Dispose(); redirect.Dispose();
        evidence.Add($"PASS start/check/stop iteration={iteration}; hotspot={actualHotspot.Address}; CDN={actualCdn}");
    }
    File.WriteAllLines(report, evidence);
    Console.WriteLine("PASS: real hotspot discovery, public resolution, WinDivert DNS/redirect startup, health and cleanup repeated three times; vehicle transfer not tested");
    return;
}

var hotspot = new HotspotInfo(5, "test", IPAddress.Parse("192.168.137.1"), 24);
var cdn = IPAddress.Parse("182.40.51.20");
long timestamp = 0;
var routes = new DownloadRouteTable(hotspot, cdn, () => timestamp);
byte[] syn = Packet("192.168.137.141", cdn.ToString(), 50001, 443, 2);
byte[] original = syn.ToArray();
Check(!routes.Translate(syn, false) && syn.AsSpan().SequenceEqual(original), "unapproved client is passed unchanged");
routes.Authorize(IPAddress.Parse("192.168.137.141"));
Check(!routes.Translate(Packet("192.168.137.141", cdn.ToString(), 50001, 443, 16), false), "existing connection is not hijacked");
Check(!routes.Translate(Packet("192.168.137.141", "1.1.1.1", 50001, 443, 2), false), "unrelated destination excluded");
Check(!routes.Translate(Packet("192.168.137.142", cdn.ToString(), 50001, 443, 2), false), "other client excluded");
Check(!routes.Translate(Packet("192.168.137.141", cdn.ToString(), 50001, 22, 2), false), "other service excluded");
Check(routes.Translate(syn, false) && new IPAddress(syn.AsSpan(16,4)).Equals(hotspot.Address), "SYN reaches local listener");
Check(syn.AsSpan(20).SequenceEqual(original.AsSpan(20)), "TCP sequence, ports, flags preserved before checksum recalculation");
byte[] reply = Packet(hotspot.Address.ToString(), "192.168.137.141", 443, 50001, 18);
Check(routes.Translate(reply, true) && new IPAddress(reply.AsSpan(12,4)).Equals(cdn), "SYN ACK appears from CDN");
Check(!routes.Translate(Packet(hotspot.Address.ToString(), "192.168.137.142", 443, 50001, 18), true), "return client isolated");
Check(!routes.Translate(Packet(hotspot.Address.ToString(), "192.168.137.141", 443, 50002, 18), true), "return port isolated");
Check(routes.Translate(Packet("192.168.137.141", cdn.ToString(), 50001, 443, 24, 512), false), "payload packet translated");
Check(routes.Translate(Packet("192.168.137.141", cdn.ToString(), 50001, 443, 17), false), "FIN translated for active flow");
Check(routes.Translate(Packet(hotspot.Address.ToString(), "192.168.137.141", 443, 50001, 4), true), "RST translated for active flow");
byte[] fragmented = Packet("192.168.137.141", cdn.ToString(), 50001, 443, 2); fragmented[6] = 0x20;
Check(!routes.Translate(fragmented, false), "fragmented IP not misparsed as TCP");
byte[] invalid = Packet("192.168.137.141", cdn.ToString(), 50001, 443, 2); invalid[32] = 0x10;
Check(!routes.Translate(invalid, false), "invalid TCP header rejected");
for (int count = 0; count < 40; count++) Check(!routes.Translate(new byte[count], false), "short packet rejected");
timestamp = 16 * 60 * 1000;
Check(!routes.Translate(Packet(hotspot.Address.ToString(), "192.168.137.141", 443, 50001, 16), true), "idle return mapping expires");
Check(!routes.Translate(Packet("192.168.137.141", cdn.ToString(), 50001, 443, 2), false), "DNS authorization expires");
routes.Authorize(IPAddress.Parse("192.168.137.141"));
Check(routes.Translate(Packet("192.168.137.141", cdn.ToString(), 50001, 443, 2), false), "fresh DNS enables reconnect and resume");
foreach (string address in new[] { "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.137.1", "169.254.1.1", "198.18.1.1", "100.64.1.1", "224.0.0.1", "::1" })
    Check(!DownloadRouteTable.IsPublic(IPAddress.Parse(address)), "private or tunnel address not used as CDN: " + address);
Check(DownloadRouteTable.IsPublic(cdn), "public CDN accepted");
try { routes.Authorize(IPAddress.Parse("192.168.1.20")); throw new InvalidOperationException("outside subnet accepted"); }
catch (ArgumentException) { }
var dns = new List<byte> { 0x12,0x34,1,0,0,1,0,0,0,0,0,0 };
foreach (string label in DownloadServer.TargetHost.Split('.')) { dns.Add((byte)label.Length); dns.AddRange(System.Text.Encoding.ASCII.GetBytes(label)); }
dns.AddRange([0,0,1,0,1]);
byte[] answer = DnsProtocol.Reply(dns.ToArray(), cdn)!;
Check(answer.AsSpan(answer.Length-4).SequenceEqual(cdn.GetAddressBytes()), "DNS uses session public address");
Check(BinaryPrimitives.ReadUInt16BigEndian(answer.AsSpan(2)) == 0x8180, "DNS flags match real vehicle experiment");
Console.WriteLine("PASS: DNS answer, client/endpoint isolation, TCP sequence preservation, SYN admission, payload/FIN/RST, malformed packets, timeout and resume");

static void Check(bool value, string description) { if (!value) throw new InvalidOperationException(description); }
static byte[] Packet(string source, string target, ushort sourcePort, ushort targetPort, byte flags, int body = 0)
{
    byte[] packet = new byte[40 + body]; packet[0]=0x45; packet[8]=64; packet[9]=6;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
    IPAddress.Parse(source).GetAddressBytes().CopyTo(packet,12); IPAddress.Parse(target).GetAddressBytes().CopyTo(packet,16);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), sourcePort); BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), targetPort);
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(24), 0x12345678); packet[32]=0x50; packet[33]=flags;
    return packet;
}
