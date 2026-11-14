using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace FlymeNative.Core;

/// <summary>Copies packets at WFP; never blocks, modifies or reinjects observed traffic.</summary>
public sealed class TrafficObserver(HotspotInfo hotspot, Action<string> log) : IDisposable
{
    private readonly List<nint> handles = [];
    private readonly List<Task> workers = [];
    private readonly ConcurrentQueue<Exception> errors = new();
    private int stopping, recorded;
    private bool started;

    internal static string Filter(HotspotInfo hotspot)
    {
        var subnet = WindowsSubnet.From(hotspot);
        string scope = $"((ip.SrcAddr >= {WindowsSubnet.Format(subnet.Network)} and ip.SrcAddr <= {WindowsSubnet.Format(subnet.Broadcast)}) or (ip.DstAddr >= {WindowsSubnet.Format(subnet.Network)} and ip.DstAddr <= {WindowsSubnet.Format(subnet.Broadcast)}))";
        return $"ip and {scope} and ((udp and (udp.SrcPort == 53 or udp.DstPort == 53)) or (tcp and ((tcp.Syn or tcp.Rst) and (tcp.SrcPort == 80 or tcp.SrcPort == 443 or tcp.DstPort == 80 or tcp.DstPort == 443) or (tcp.DstPort == 443 and tcp.PayloadLength > 0))))";
    }

    public void Start()
    {
        if (started) throw new InvalidOperationException("网络观测只能启动一次。");
        if (!WindowsNetwork.IsAdministrator) throw new InvalidOperationException("网络观测需要管理员权限。");
        started = true;
        try
        {
            for (int layer = 0; layer <= 1; layer++)
            {
                // Lower priority than the DNS injector (-100) also sees its injected response.
                nint handle = WinDivertNative.Open(Filter(hotspot), layer, -200, 5);
                if (handle == -1) throw new Win32Exception(Marshal.GetLastPInvokeError(), $"只读观测启动失败 layer={layer}");
                handles.Add(handle);
                int observedLayer = layer;
                workers.Add(Task.Factory.StartNew(() => Run(handle, observedLayer), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default));
            }
            log($"[网络观测启动] 1.0.9; 子网={hotspot.Address}/{hotspot.PrefixLength}; SNIFF|RECV_ONLY; 不改包；包含完整单包ClientHello的SNI，分片握手可能不显示；前512条事件");
        }
        catch { Dispose(); throw; }
    }

    private unsafe void Run(nint handle, int layer)
    {
        try
        {
            byte[] bytes = new byte[65575];
            fixed (byte* buffer = bytes)
            {
                while (WinDivertNative.Receive(handle, buffer, (uint)bytes.Length, out uint length, out WinDivertAddress address))
                {
                    string? description = Describe(bytes.AsSpan(0, checked((int)length)));
                    if (description is null) continue;
                    int count = Interlocked.Increment(ref recorded);
                    if (count <= 512)
                        log($"[WFP观察] layer={layer}; direction={((address.Flags & (1u << 17)) != 0 ? "出站" : "入站/转发")}; ifIdx={address.InterfaceIndex}; {description}");
                    else if (count == 513) log("[网络观测] 已达到512条上限；继续被动接收但停止写入观测日志。");
                }
                int error = Marshal.GetLastPInvokeError();
                if (Volatile.Read(ref stopping) == 0 || error != 232)
                    throw new Win32Exception(error, "只读网络观测接收失败。");
            }
        }
        catch (Exception error) { errors.Enqueue(error); log($"[网络观测失败] {error}"); }
    }

    internal static string? Describe(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20 || packet[0] >> 4 != 4) return null;
        int header = (packet[0] & 15) * 4;
        if (header < 20 || header + 8 > packet.Length || (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3fff) != 0) return null;
        string source = new IPAddress(packet.Slice(12, 4)).ToString(), destination = new IPAddress(packet.Slice(16, 4)).ToString();
        var body = packet[header..];
        ushort from = BinaryPrimitives.ReadUInt16BigEndian(body), to = BinaryPrimitives.ReadUInt16BigEndian(body[2..]);
        if (packet[9] == 6)
        {
            if (body.Length < 20) return null;
            int tcpHeader = (body[12] >> 4) * 4;
            if (to == 443 && tcpHeader >= 20 && tcpHeader < body.Length)
            {
                string? name = TlsHelloObservation.ServerName(body[tcpHeader..]);
                if (name is not null && (name.Equals("flymeauto.com", StringComparison.Ordinal) || name.EndsWith(".flymeauto.com", StringComparison.Ordinal)))
                    return $"[TLS域名] {source}:{from} -> {destination}:{to}; SNI={name}; 下载域名={name == DownloadServer.TargetHost}";
            }
            if ((body[13] & 6) == 0) return null;
            return $"TCP {source}:{from} -> {destination}:{to}; SYN={(body[13] & 2) != 0}; ACK={(body[13] & 16) != 0}; RST={(body[13] & 4) != 0}";
        }
        if (packet[9] != 17 || (from != 53 && to != 53) || body.Length < 25) return null;
        var dns = body[8..];
        if (from == 53 && (dns[2] & 0x80) != 0)
        {
            string? response = NicDnsAudit.Describe(packet, 101);
            return response is null ? null : "DNS response=True; " + response;
        }
        if (BinaryPrimitives.ReadUInt16BigEndian(dns[4..]) != 1) return null;
        int cursor = 12;
        List<string> labels = [];
        while (cursor < dns.Length)
        {
            int count = dns[cursor++];
            if (count == 0) break;
            if (count > 63 || cursor + count > dns.Length) return null;
            labels.Add(System.Text.Encoding.ASCII.GetString(dns.Slice(cursor, count)));
            cursor += count;
        }
        if (!string.Join('.', labels).Equals(DownloadServer.TargetHost, StringComparison.OrdinalIgnoreCase) || cursor + 4 > dns.Length) return null;
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(dns[2..]);
        string answer = "无/未解码";
        int pos = cursor + 4;
        if (BinaryPrimitives.ReadUInt16BigEndian(dns[6..]) > 0 && pos + 16 <= dns.Length && dns[pos] == 0xc0 &&
            BinaryPrimitives.ReadUInt16BigEndian(dns[(pos + 2)..]) == 1 && BinaryPrimitives.ReadUInt16BigEndian(dns[(pos + 10)..]) == 4)
            answer = new IPAddress(dns.Slice(pos + 12, 4)).ToString();
        return $"DNS {source}:{from} -> {destination}:{to}; txid={BinaryPrimitives.ReadUInt16BigEndian(dns):X4}; response={(flags & 0x8000) != 0}; rcode={flags & 15}; QTYPE={BinaryPrimitives.ReadUInt16BigEndian(dns[cursor..])}; A={answer}";
    }

    public void CheckHealth()
    {
        if (!errors.IsEmpty) throw new AggregateException("网络观测故障。", errors);
        if (started && Volatile.Read(ref stopping) == 0 && workers.Any(task => task.IsCompleted))
            throw new InvalidOperationException("网络观测线程提前退出。");
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref stopping, 1) != 0) return;
        foreach (nint handle in handles)
            if (!WinDivertNative.Shutdown(handle, 1)) errors.Enqueue(new Win32Exception(Marshal.GetLastPInvokeError(), "停止只读观测失败。"));
        if (!Task.WaitAll(workers.ToArray(), TimeSpan.FromSeconds(5)))
        {
            foreach (nint handle in handles) WinDivertNative.Close(handle);
            Task.WaitAll(workers.ToArray(), TimeSpan.FromSeconds(5));
            throw new TimeoutException("只读网络观测退出超时。");
        }
        foreach (nint handle in handles)
            if (!WinDivertNative.Close(handle)) errors.Enqueue(new Win32Exception(Marshal.GetLastPInvokeError(), "关闭只读观测失败。"));
        handles.Clear();
        CheckHealth();
    }
}
