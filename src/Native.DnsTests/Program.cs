#:project ../Native.Core/Native.Core.csproj
#:property AssemblyName=Native.DnsTests
#:property AllowUnsafeBlocks=true
#:property TargetFramework=net10.0
using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using FlymeNative.Core;

var gateway = IPAddress.Parse("192.168.77.1");
int checks = 0;
void Check(bool condition, string message)
{
    checks++;
    if (!condition) throw new InvalidOperationException(message);
}
byte[] Query(string name, ushort type = 1)
{
    var bytes = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    foreach (string label in name.Split('.'))
    {
        bytes.Add((byte)label.Length);
        bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
    }
    bytes.AddRange([0, (byte)(type >> 8), (byte)type, 0, 1]);
    return bytes.ToArray();
}
byte[] target = Query("carapp-a-res.flymeauto.com");
byte[] response = DnsProtocol.Reply(target, gateway) ?? throw new InvalidOperationException("Target A missing");
byte[] capturedDns = Convert.FromHexString(File.ReadAllText("fixtures/dns-response.hex").Trim());
byte[] patchedDns = DnsAnswerPatch.ReplaceAddresses(capturedDns, gateway) ?? throw new InvalidOperationException("Captured CNAME response not patched");
Check(patchedDns.Length == capturedDns.Length, "Observed vehicle DNS response length preserved");
Check(patchedDns.AsSpan(0, 12).SequenceEqual(capturedDns.AsSpan(0, 12)), "Original 0x8100 flags and 13-answer header preserved");
byte[] expectedDns = (byte[])capturedDns.Clone();
byte[] zeroTtlARecord = Convert.FromHexString("00010001000000000004");
int fixtureAnswers = 0;
for (int index = 0; index <= capturedDns.Length - zeroTtlARecord.Length - 4; index++)
    if (capturedDns.AsSpan(index, zeroTtlARecord.Length).SequenceEqual(zeroTtlARecord))
    {
        gateway.GetAddressBytes().CopyTo(expectedDns.AsSpan(index + zeroTtlARecord.Length));
        fixtureAnswers++;
    }
Check(fixtureAnswers == 12 && expectedDns.SequenceEqual(patchedDns), "Only twelve captured zero-TTL A RDATA fields change; every other byte stays identical");
int localAnswers = 0;
for (int offset = 0; offset <= patchedDns.Length - 4; offset++)
    if (patchedDns.AsSpan(offset, 4).SequenceEqual(gateway.GetAddressBytes())) localAnswers++;
Check(localAnswers == 12, "All twelve CDN A answers replaced, not just the first");
Check(patchedDns.AsSpan(12, 167).SequenceEqual(capturedDns.AsSpan(12, 167)), "Captured question and CNAME chain preserved byte-for-byte");
Check(DnsAnswerPatch.ReplaceAddresses(capturedDns.AsSpan(0, capturedDns.Length - 1), gateway) is null, "Truncated final DNS resource record rejected");
byte[] CaptureIp(byte[] dns)
{
    byte[] ip = new byte[28 + dns.Length];
    ip[0] = 0x45; ip[9] = 17;
    new byte[] { 192, 168, 77, 1, 192, 168, 77, 12 }.CopyTo(ip.AsSpan(12));
    BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), (ushort)ip.Length);
    BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(20), 53);
    BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(22), 50000);
    BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(24), (ushort)(dns.Length + 8));
    dns.CopyTo(ip.AsSpan(28));
    return ip;
}
byte[] capturedIp = CaptureIp(capturedDns), modifiedIp = CaptureIp(patchedDns);
string? originalSummary = NicDnsAudit.Describe(capturedIp, 101);
Check(originalSummary?.Contains("150.139.243.53", StringComparison.Ordinal) == true, "NIC audit decodes captured A after uncompressed CNAME");
Check(NicDnsAudit.Describe(modifiedIp, 101)?.Contains("A=[192.168.77.1]", StringComparison.Ordinal) == true, "NIC audit verifies all changed A answers independently of WFP summary");
Check(TrafficObserver.Describe(capturedIp)?.Contains("150.139.243.53", StringComparison.Ordinal) == true,
    "WFP observation uses complete original CNAME chain and CDN addresses");
Check(TrafficObserver.Describe(modifiedIp)?.Contains("A=[192.168.77.1]", StringComparison.Ordinal) == true,
    "WFP observation displays patched multi-answer response instead of undecoded");
byte[] ethernetDns = [.. new byte[12], 8, 0, .. modifiedIp];
Check(NicDnsAudit.Describe(ethernetDns, 1)?.Contains("txid=E20E", StringComparison.Ordinal) == true, "NIC Ethernet frame transaction decoded");
for (int prefix = 0; prefix < ethernetDns.Length; prefix++)
    _ = NicDnsAudit.Describe(ethernetDns.AsSpan(0, prefix), 1);
Check(NicDnsAudit.Describe(ethernetDns, 999) is null, "Unsupported capture link type not guessed");
byte[] actualWirelessHeader = Convert.FromHexString("0802008024197250CE63C6FF99B75115C6FF99B751150000AAAA030000000800");
byte[] mislabeledWirelessDns = [.. actualWirelessHeader, .. modifiedIp];
Check(NicDnsAudit.Describe(mislabeledWirelessDns, 1)?.Contains("A=[192.168.77.1]", StringComparison.Ordinal) == true,
    "Actual PktMon Wi-Fi frame mislabeled Ethernet decodes target CNAME response");
Check(NicDnsAudit.Describe(mislabeledWirelessDns, 105)?.Contains("txid=E20E", StringComparison.Ordinal) == true,
    "Explicit raw 802.11 link type decodes identically");
Check(response.AsSpan(0, 2).SequenceEqual(target.AsSpan(0, 2)), "Transaction ID");
Check(response[2] == 0x81 && response[3] == 0x80, "Recursive response/RD/RA flags without claiming authority");
Check(BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)) == 1, "A answer count");
Check(response.AsSpan(response.Length - 4).SequenceEqual(gateway.GetAddressBytes()), "Gateway A data");
Check(response.AsSpan(12, target.Length - 12).SequenceEqual(target.AsSpan(12)), "Question preservation");
foreach (ushort type in new ushort[] { 28, 64, 65 })
{
    byte[] q = Query("CARAPP-A-RES.FLYMEAUTO.COM", type);
    byte[] r = DnsProtocol.Reply(q, gateway) ?? throw new InvalidOperationException("Empty response missing");
    Check(r.Length == q.Length && r[6] == 0 && r[7] == 0, $"Type {type} NODATA");
}
foreach (string name in new[] { "other.flymeauto.com", "carapp-a-res.flymeauto.com.evil", "xcarapp-a-res.flymeauto.com" })
    Check(DnsProtocol.Reply(Query(name), gateway) is null, "Exact target only");
Check(DnsProtocol.Reply(Query("carapp-a-res.flymeauto.com", 15), gateway) is null, "Other qtype passes through");
for (int size = 0; size < target.Length; size++)
    Check(DnsProtocol.Reply(target.AsSpan(0, size), gateway) is null, "Truncated query");
byte[] malformed = (byte[])target.Clone();
malformed[12] = 0xc0; malformed[13] = 12;
Check(DnsProtocol.Reply(malformed, gateway) is null, "Compression cycle rejected");
malformed = (byte[])target.Clone(); malformed[5] = 2;
Check(DnsProtocol.Reply(malformed, gateway) is null, "Multiple questions rejected");
malformed = (byte[])target.Clone(); malformed[2] = 0x81;
Check(DnsProtocol.Reply(malformed, gateway) is null, "Response passes through");
byte[] dottedLabel = [.. target.AsSpan(0, 12), 22, .. System.Text.Encoding.ASCII.GetBytes("carapp-a-res.flymeauto"), 3, (byte)'c', (byte)'o', (byte)'m', 0, 0, 1, 0, 1];
Check(DnsProtocol.Reply(dottedLabel, gateway) is null, "Literal dot inside a label is not a target separator");
byte[] opt = [.. target, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0];
opt[11] = 1;
Check(DnsProtocol.Reply(opt, gateway)?.Length == response.Length, "EDNS query accepted without copying options");
opt[^1] = 5;
Check(DnsProtocol.Reply(opt, gateway) is null, "Truncated OPT rejected");
byte[] compressed = [.. target.AsSpan(0, 12), 0xc0, 18, 0, 1, 0, 1, .. target.AsSpan(12, target.Length - 16)];
Check(DnsProtocol.Reply(compressed, gateway) is null, "Unclaimed compression storage rejected");
byte[] compressedOpt = [.. target.AsSpan(0, 12), 0xc0, 33, 0, 1, 0, 1,
    0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 32, 0, 12, 0, 28, .. target.AsSpan(12, 28)];
compressedOpt[11] = 1;
Check(DnsProtocol.Reply(compressedOpt, gateway)?.SequenceEqual(response) == true, "Compressed name safely rebuilt independently of OPT storage");
var random = new Random(17);
for (int i = 0; i < 10000; i++)
{
    byte[] noise = new byte[random.Next(0, 512)];
    random.NextBytes(noise);
    Check(DnsProtocol.Reply(noise, gateway) is null, "Random input passes through");
}
byte[] packet = new byte[28 + target.Length];
packet[0] = 0x45; packet[8] = 128; packet[9] = 17;
BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
new byte[] { 192, 168, 77, 12, 8, 8, 8, 8 }.CopyTo(packet.AsSpan(12));
BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), 50123);
BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), 53);
BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24), (ushort)(packet.Length - 20));
target.CopyTo(packet.AsSpan(28));
byte[] originalPacket = (byte[])packet.Clone();
byte[] rawReply = DnsPacket.Reply(packet, gateway) ?? throw new InvalidOperationException("Raw DNS packet missing");
var gatewayExchange = new GatewayDnsExchange(gateway);
byte[] gatewayQuery = (byte[])packet.Clone();
gateway.GetAddressBytes().CopyTo(gatewayQuery.AsSpan(16));
Check(gatewayExchange.Remember(gatewayQuery), "Gateway target query recorded while preserving query delivery");
byte[] systemResponse = DnsPacket.Reply(gatewayQuery, IPAddress.Parse("180.101.49.121")) ?? throw new InvalidOperationException("System response fixture");
byte[] systemBefore = (byte[])systemResponse.Clone();
byte[] rewrittenSystem = gatewayExchange.Rewrite(systemResponse) ?? throw new InvalidOperationException("System response rewrite missing");
Check(systemResponse.SequenceEqual(systemBefore), "System response input preserved");
Check(rewrittenSystem.AsSpan(12, 12).SequenceEqual(systemResponse.AsSpan(12, 12)), "System IP endpoints and UDP ports preserved");
Check(rewrittenSystem.AsSpan(rewrittenSystem.Length - 4).SequenceEqual(gateway.GetAddressBytes()), "Real CDN answer replaced by local gateway");
Check(gatewayExchange.Rewrite(systemResponse) is null, "Unmatched or already consumed response passes unchanged");
Check(!gatewayExchange.Remember(originalPacket), "External DNS target not consumed by gateway exchange");
Check(gatewayExchange.Remember(gatewayQuery), "New gateway exchange recorded");
byte[] wrongTransaction = (byte[])systemResponse.Clone(); wrongTransaction[28] ^= 1;
Check(gatewayExchange.Rewrite(wrongTransaction) is null, "Wrong DNS transaction ID never rewritten");
Check(gatewayExchange.Rewrite(systemResponse) is not null, "Original matching transaction survives unrelated response");
Check(gatewayExchange.Remember(gatewayQuery), "Original reinjection control query recorded");
byte[] originalControl = gatewayExchange.Rewrite(systemResponse, preserveOriginal: true) ?? throw new InvalidOperationException("Original control missing");
Check(originalControl.SequenceEqual(systemResponse), "Original reinjection preserves every IP/UDP/DNS byte including checksum/offload fields");
Check(gatewayExchange.Remember(gatewayQuery), "Question mismatch test recorded");
byte[] wrongQuestion = (byte[])systemResponse.Clone(); wrongQuestion[41] = (byte)'x';
Check(gatewayExchange.Rewrite(wrongQuestion) is null, "Same transaction with another DNS question rejected");
Check(gatewayExchange.Rewrite(systemResponse) is not null, "Question mismatch does not consume genuine pending query");
Check(gatewayExchange.Remember(gatewayQuery), "Invalid answer test recorded");
byte[] invalidAnswer = (byte[])systemResponse.Clone(); invalidAnswer[^5] ^= 1;
Check(gatewayExchange.Rewrite(invalidAnswer) is null, "Malformed answer rejected before consuming pending query");
Check(gatewayExchange.Rewrite(systemResponse) is not null, "Genuine response survives malformed same-transaction answer");
Check(gatewayExchange.Remember(gatewayQuery), "Case variation test recorded");
byte[] uppercaseQuestion = (byte[])systemResponse.Clone(); uppercaseQuestion[41] = (byte)'C';
Check(gatewayExchange.Rewrite(uppercaseQuestion, preserveOriginal: true)?.SequenceEqual(uppercaseQuestion) == true,
    "DNS response question case variation accepted without altering original control bytes");
Check(packet.SequenceEqual(originalPacket), "Request bytes preserved");
Check(rawReply.AsSpan(12, 4).SequenceEqual(packet.AsSpan(16, 4)), "Response source is queried DNS server");
Check(rawReply.AsSpan(16, 4).SequenceEqual(packet.AsSpan(12, 4)), "Response destination is client");
Check(BinaryPrimitives.ReadUInt16BigEndian(rawReply.AsSpan(22)) == 50123, "Client port preserved");
uint WireSum(ReadOnlySpan<byte> bytes)
{
    uint sum = 0;
    for (int i = 0; i < bytes.Length; i++) sum += (uint)bytes[i] << (i % 2 == 0 ? 8 : 0);
    while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
    return sum;
}
Check(WireSum(rawReply.AsSpan(0, 20)) == 65535, "IPv4 checksum independent oracle");
Check(WireSum(rewrittenSystem.AsSpan(0, 20)) == 65535, "Rewritten system IPv4 checksum independent oracle");
byte[] rewrittenPseudo = [.. rewrittenSystem.AsSpan(12, 8), 0, 17, (byte)((rewrittenSystem.Length - 20) >> 8), (byte)(rewrittenSystem.Length - 20), .. rewrittenSystem.AsSpan(20)];
Check(WireSum(rewrittenPseudo) == 65535, "Rewritten system UDP checksum independent oracle");
byte[] pseudo = [.. rawReply.AsSpan(12, 8), 0, 17, (byte)((rawReply.Length - 20) >> 8), (byte)(rawReply.Length - 20), .. rawReply.AsSpan(20)];
Check(WireSum(pseudo) == 65535, "UDP pseudoheader checksum independent oracle");
Check(NicDnsAudit.Describe(rawReply, 101)?.Contains("IPv4校验和=True; UDP校验和=通过", StringComparison.Ordinal) == true,
    "NIC audit independently confirms valid IPv4 and UDP checksums");
byte[] damagedWire = (byte[])rawReply.Clone(); damagedWire[^1] ^= 1;
Check(NicDnsAudit.Describe(damagedWire, 101)?.Contains("UDP校验和=不匹配", StringComparison.Ordinal) == true,
    "NIC audit detects a changed DNS byte without a matching checksum");
packet[6] = 0x20;
Check(DnsPacket.Reply(packet, gateway) is null, "IP fragments pass through");
packet = (byte[])originalPacket.Clone(); packet[25]--;
Check(DnsPacket.Reply(packet, gateway) is null, "UDP length mismatch passes through");
packet = (byte[])originalPacket.Clone(); packet[9] = 6;
Check(DnsPacket.Reply(packet, gateway) is null, "TCP passes through");
packet = (byte[])originalPacket.Clone(); packet[^3] = 15;
Check(DnsPacket.Reply(packet, gateway) is null && packet[^3] == 15, "Unsupported query is returned to caller untouched");
Check(Marshal.SizeOf<WinDivertAddress>() == 80, "WinDivert ABI size");
Check(Marshal.OffsetOf<WinDivertAddress>(nameof(WinDivertAddress.Flags)) == 8, "WinDivert flags offset");
Check(Marshal.OffsetOf<WinDivertAddress>(nameof(WinDivertAddress.InterfaceIndex)) == 16, "WinDivert ifIdx offset");
Check(Marshal.OffsetOf<WinDivertAddress>(nameof(WinDivertAddress.SubInterfaceIndex)) == 20, "WinDivert subIfIdx offset");
var hotspot = new HotspotInfo(17, "Test hotspot", gateway, 24);
byte[] Hello(string hostname)
{
    static byte[] Sized(byte[] value) => [(byte)(value.Length >> 8), (byte)value.Length, .. value];
    byte[] name = System.Text.Encoding.ASCII.GetBytes(hostname);
    byte[] sni = Sized([0, .. Sized(name)]);
    byte[] extensions = Sized([0, 0, .. Sized(sni)]);
    byte[] content = [3, 3, .. new byte[32], 0, 0, 2, 0x13, 1, 1, 0, .. extensions];
    byte[] handshake = [1, (byte)(content.Length >> 16), (byte)(content.Length >> 8), (byte)content.Length, .. content];
    return [22, 3, 1, .. Sized(handshake)];
}
byte[] hello = Hello("carapp-a-res.flymeauto.com");
Check(TlsHelloObservation.ServerName(hello) == DownloadServer.TargetHost, "ClientHello actual SNI parsed");
Check(TlsHelloObservation.ServerName(Hello("api-carapp.flymeauto.com")) == "api-carapp.flymeauto.com", "API SNI remains distinct from download domain");
for (int prefix = 0; prefix < hello.Length; prefix++)
    Check(TlsHelloObservation.ServerName(hello.AsSpan(0, prefix)) is null, "Fragmented or truncated ClientHello not invented");
Check(TlsHelloObservation.ServerName(Hello("invalid\nname")) is null, "SNI log control characters rejected");
Check(TrafficObserver.Describe(originalPacket)?.Contains("response=False", StringComparison.Ordinal) == true, "Observer decodes actual target DNS query");
Check(TrafficObserver.Describe(rawReply)?.Contains("A=[192.168.77.1]", StringComparison.Ordinal) == true, "Observer independently displays injected DNS answer");
Check(TrafficObserver.Describe(rawReply)?.Contains("response=True", StringComparison.Ordinal) == true, "Observer distinguishes DNS response from query");
byte[] syn = new byte[40];
syn[0] = 0x45; syn[9] = 6; originalPacket.AsSpan(12, 8).CopyTo(syn.AsSpan(12));
BinaryPrimitives.WriteUInt16BigEndian(syn.AsSpan(20), 55000);
BinaryPrimitives.WriteUInt16BigEndian(syn.AsSpan(22), 443);
syn[33] = 2;
Check(TrafficObserver.Describe(syn)?.Contains("SYN=True", StringComparison.Ordinal) == true, "Observer decodes HTTPS SYN");
syn[33] = 20;
Check(TrafficObserver.Describe(syn)?.Contains("RST=True", StringComparison.Ordinal) == true, "Observer decodes RST ACK");
syn[33] = 16;
Check(TrafficObserver.Describe(syn) is null, "Observer omits ordinary TCP ACK payload traffic");
string[] firewall = WindowsFirewall.AddArguments("owned-rule", hotspot);
Check(firewall.Contains("localip=192.168.77.1") && firewall.Contains("remoteip=192.168.77.0/24") &&
    firewall.Contains("localport=80,443") && firewall.Contains("protocol=TCP"), "Scoped firewall command");
using (var interceptor = new DnsInterceptor(hotspot))
{
    bool unhealthy = false;
    try { interceptor.CheckHealth(); }
    catch (InvalidOperationException) { unhealthy = true; }
    Check(unhealthy && interceptor.Hits == 0, "Unstarted interceptor cannot report healthy");
}
if (OperatingSystem.IsWindows())
{
    if (!WindowsNetwork.IsAdministrator)
    {
        using var denied = new DnsInterceptor(hotspot);
        bool rejected = false;
        try { denied.Start(); }
        catch (InvalidOperationException) { rejected = true; }
        Check(rejected, "Unprivileged startup rejected before loading WinDivert");
        bool firewallRejected = false;
        try { using IDisposable rule = WindowsNetwork.AllowDownloads(hotspot); }
        catch (InvalidOperationException) { firewallRejected = true; }
        Check(firewallRejected, "Unprivileged firewall setup rejected before netsh");
    }
    string dll = Path.GetFullPath("drivers/WinDivert64.dll");
    nint library = NativeLibrary.Load(dll);
    NativeLibrary.SetDllImportResolver(typeof(DnsProtocol).Assembly, (name, _, _) => name == "WinDivert64.dll" ? library : 0);
    Check(NativeLibrary.TryGetExport(library, "WinDivertHelperCompileFilter", out _), "Native filter compiler export");
    foreach (int layer in new[] { 0, 1 })
    {
        string observerFilter = TrafficObserver.Filter(hotspot);
        Check(WinDivertNative.CompileFilter(observerFilter, layer, 0, 0, out nint observerError, out uint observerPosition),
            $"Passive observer filter compiles layer {layer}: {Marshal.PtrToStringAnsi(observerError)} at {observerPosition}");
        string filter = DnsInterceptor.Filter(hotspot, layer);
        bool valid = WinDivertNative.CompileFilter(filter, layer, 0, 0, out nint error, out uint position);
        Check(valid, $"Native layer {layer} filter compile: {Marshal.PtrToStringAnsi(error)} at {position}");
        unsafe
        {
            byte[] input = (byte[])originalPacket.Clone();
            WinDivertAddress metadata = new() { Flags = (uint)layer, InterfaceIndex = 17 };
            fixed (byte* data = input)
            {
                Check(WinDivertNative.EvaluateFilter(filter, data, (uint)input.Length, in metadata), "Hotspot DNS matches native filter");
                input[12] = 10;
                Check(!WinDivertNative.EvaluateFilter(filter, data, (uint)input.Length, in metadata), "Other subnet rejected by native filter");
                input[12] = 192; input[15] = 1;
                Check(!WinDivertNative.EvaluateFilter(filter, data, (uint)input.Length, in metadata), "Gateway rejected by native filter");
                input[15] = 12; input[23] = 54;
                Check(!WinDivertNative.EvaluateFilter(filter, data, (uint)input.Length, in metadata), "Other UDP port rejected by native filter");
                input[23] = 53;
                if (layer == 0)
                {
                    metadata.InterfaceIndex = 18;
                    Check(!WinDivertNative.EvaluateFilter(filter, data, (uint)input.Length, in metadata), "Other interface rejected by NETWORK filter");
                    metadata.InterfaceIndex = 17; metadata.Flags |= 1u << 17;
                    Check(!WinDivertNative.EvaluateFilter(filter, data, (uint)input.Length, in metadata), "Outbound rejected by NETWORK filter");
                }
            }
        }
        Console.WriteLine($"Validated layer {layer}: {filter}");
    }
    Check(!WinDivertNative.CompileFilter("invalid filter (", 0, 0, 0, out _, out _), "Invalid filter rejected by real native compiler");
    Console.WriteLine("Native helper validation only: no WinDivertOpen, driver startup, or firewall command executed.");
}
Console.WriteLine($"PASS: {checks} total DNS/wire/ABI/filter/firewall/lifecycle checks");
if (args.Length == 1) NicDnsAudit.Summarize(args[0], Console.WriteLine);
