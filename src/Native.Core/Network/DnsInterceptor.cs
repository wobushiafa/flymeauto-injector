using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace FlymeNative.Core;

public sealed class DnsInterceptor : IDisposable
{
    private readonly HotspotInfo hotspot;
    private readonly Action<string>? log;
    private readonly object gate = new();
    private readonly ConcurrentQueue<Exception> failures = new();
    private readonly ConcurrentDictionary<nint, byte> closedHandles = new();
    private readonly List<nint> captureHandles = [];
    private readonly List<Task> workers = [];
    private nint sendHandle;
    private bool attempted, disposed;
    private int stopping, hits;
    private readonly GatewayDnsExchange gatewayDns;
    private readonly bool rewriteAnswers;
    private readonly System.Net.IPAddress? downloadAddress;
    private readonly Action<System.Net.IPAddress>? answered;

    public DnsInterceptor(HotspotInfo hotspot, Action<string>? log = null, bool rewriteAnswers = true,
        System.Net.IPAddress? downloadAddress = null, Action<System.Net.IPAddress>? answered = null)
    {
        _ = WindowsSubnet.From(hotspot);
        this.hotspot = hotspot;
        this.log = log;
        gatewayDns = new GatewayDnsExchange(hotspot.Address);
        this.rewriteAnswers = rewriteAnswers;
        this.downloadAddress = downloadAddress;
        this.answered = answered;
    }

    public int Hits => Volatile.Read(ref hits);

    internal static string Filter(HotspotInfo hotspot, int layer)
    {
        string clients = WindowsSubnet.From(hotspot).ClientFilter(hotspot);
        return layer switch
        {
            0 => $"(({clients}) and inbound and !loopback and ifIdx == {hotspot.InterfaceIndex}) or (outbound and ip and udp.SrcPort == 53 and ip.SrcAddr == {hotspot.Address} and ip.DstAddr > {WindowsSubnet.Format(WindowsSubnet.From(hotspot).Network)} and ip.DstAddr < {WindowsSubnet.Format(WindowsSubnet.From(hotspot).Broadcast)})",
            1 => clients,
            _ => throw new ArgumentOutOfRangeException(nameof(layer))
        };
    }

    public void Start()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (attempted) throw new InvalidOperationException("DNS interceptor can only be started once.");
            if (!OperatingSystem.IsWindows() || !WindowsNetwork.IsAdministrator)
                throw new InvalidOperationException("WinDivert DNS interception requires Windows administrator rights.");
            attempted = true;
            try
            {
                sendHandle = WinDivertNative.OpenChecked("false", 0, 8);
                captureHandles.Add(WinDivertNative.OpenChecked(Filter(hotspot, 0), 0, 0));
                captureHandles.Add(WinDivertNative.OpenChecked(Filter(hotspot, 1), 1, 0));
                foreach (nint handle in captureHandles)
                    workers.Add(Task.Factory.StartNew(() => Run(handle), CancellationToken.None,
                        TaskCreationOptions.LongRunning, TaskScheduler.Default));
                log?.Invoke($"[DNS启动] interface={hotspot.InterfaceIndex}; name={hotspot.Name}; gateway={hotspot.Address}/{hotspot.PrefixLength}; NETWORK={Filter(hotspot, 0)}; FORWARD={Filter(hotspot, 1)}");
                log?.Invoke(downloadAddress is not null ? $"[DNS策略] 目标域名返回本次解析的公网IPv4 {downloadAddress}；下载连接透明转接至热点服务，不返回私网地址。" : rewriteAnswers
                    ? "[DNS策略] 网关A查询保留系统DNS结构，仅替换A地址；外部DNS查询采用注入响应。"
                    : "[DNS策略] 原包回注对照：系统DNS回答不改任何字节或发送元数据，只截获并原样回注；不替换下载。");
                log?.Invoke("DNS interception: IPv4 UDP/53 only; TCP DNS, IPv6 DNS, DoH/DoT and cached answers are outside interception. HTTPS still depends on client TLS trust.");
                CheckHealth();
            }
            catch (Exception startError)
            {
                failures.Enqueue(startError);
                Cleanup();
                disposed = true;
                throw new AggregateException("DNS interceptor startup failed.", failures);
            }
        }
    }

    public void CheckHealth()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!failures.IsEmpty) throw new AggregateException("DNS interception failed.", failures);
            if (!attempted || workers.Count != 2 || workers.Any(worker => worker.IsCompleted))
                throw new InvalidOperationException("DNS interception is not running.");
        }
    }

    private unsafe void Run(nint handle)
    {
        try
        {
            byte[] packet = new byte[65575];
            fixed (byte* buffer = packet)
            {
                while (true)
                {
                    if (!WinDivertNative.Receive(handle, buffer, (uint)packet.Length, out uint length, out WinDivertAddress address))
                    {
                        int error = Marshal.GetLastPInvokeError();
                        if (error == 232 && Volatile.Read(ref stopping) != 0) return;
                        throw new Win32Exception(error, "WinDivert receive failed.");
                    }
                    var incoming = packet.AsSpan(0, checked((int)length));
                    if (downloadAddress is null && Volatile.Read(ref stopping) == 0 && gatewayDns.Remember(incoming))
                    {
                        if (!WinDivertNative.Send(handle, buffer, length, out uint forwarded, in address) || forwarded != length)
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "网关DNS查询放行失败。");
                        log?.Invoke($"[DNS查询放行] client={new System.Net.IPAddress(packet.AsSpan(12, 4))}; txid={System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan((packet[0] & 15) * 4 + 8)):X4}; 等待ICS系统回包，不提前计入命中");
                        continue;
                    }
                    byte[]? systemReply = downloadAddress is null && Volatile.Read(ref stopping) == 0 ? gatewayDns.Rewrite(incoming, preserveOriginal: !rewriteAnswers) : null;
                    if (systemReply is not null)
                    {
                        if (!rewriteAnswers)
                        {
                            if (!WinDivertNative.Send(handle, buffer, length, out uint originalLength, in address) || originalLength != length)
                                throw new Win32Exception(Marshal.GetLastPInvokeError(), "DNS原包回注失败。");
                            Interlocked.Increment(ref hits);
                            log?.Invoke($"[DNS原包回注] #{Hits}; {TrafficObserver.Describe(incoming)}; 字节与原发送元数据完全不变");
                            continue;
                        }
                        log?.Invoke($"[DNS原包摘要] {TrafficObserver.Describe(incoming)}; 原DNS载荷hex={Convert.ToHexString(incoming[((incoming[0] & 15) * 4 + 8)..])}");
                        var sameRoute = address;
                        sameRoute.Flags |= (1u << 21) | (1u << 23);
                        fixed (byte* rewritten = systemReply)
                            if (!WinDivertNative.Send(handle, rewritten, (uint)systemReply.Length, out uint rewrittenLength, in sameRoute) || rewrittenLength != systemReply.Length)
                                throw new Win32Exception(Marshal.GetLastPInvokeError(), "系统DNS回包替换失败。");
                        Interlocked.Increment(ref hits);
                        log?.Invoke($"[DNS系统回包替换] #{Hits}; client={new System.Net.IPAddress(systemReply.AsSpan(16, 4))}; A={hotspot.Address}; txid={System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(systemReply.AsSpan((systemReply[0] & 15) * 4 + 8)):X4}; ifIdx={address.InterfaceIndex}; 保留系统回包路径");
                        continue;
                    }
                    byte[]? reply = Volatile.Read(ref stopping) == 0 && rewriteAnswers ? DnsPacket.Reply(incoming, downloadAddress ?? hotspot.Address) : null;
                    if (reply is null)
                    {
                        if (!WinDivertNative.Send(handle, buffer, length, out uint sent, in address) || sent != length)
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "WinDivert original packet reinjection failed.");
                        continue;
                    }
                    var sourceIp = new System.Net.IPAddress(packet.AsSpan(12, 4));
                    answered?.Invoke(sourceIp);
                    WinDivertAddress outbound = new() { Flags = 1u << 17, InterfaceIndex = (uint)hotspot.InterfaceIndex };
                    fixed (byte* response = reply)
                    {
                        if (!WinDivertNative.CalculateChecksums(response, (uint)reply.Length, ref outbound, 0))
                            throw new InvalidOperationException("DNS响应校验和计算失败。");
                        if (!WinDivertNative.Send(sendHandle, response, (uint)reply.Length, out uint sent, in outbound) || sent != reply.Length)
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "WinDivert DNS response injection failed.");
                    }
                    Interlocked.Increment(ref hits);
                    int ipHeader = (packet[0] & 15) * 4;
                    var dnsIp = new System.Net.IPAddress(packet.AsSpan(16, 4));
                    ushort sourcePort = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipHeader, 2));
                    int questionEnd = reply.Length - (System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(34, 2)) == 1 ? 16 : 0);
                    ushort queryType = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(questionEnd - 4, 2));
                    log?.Invoke($"[DNS命中] #{Hits}; client={sourceIp}:{sourcePort}; DNS={dnsIp}:53; domain={DownloadServer.TargetHost}; QTYPE={queryType}; A返回={downloadAddress ?? hotspot.Address}; ifIdx={address.InterfaceIndex}; 已注入响应，等待TCP连接");
                }
            }
        }
        catch (Exception error)
        {
            failures.Enqueue(error);
            log?.Invoke($"[DNS线程失败] {error}");
            StopReceiving();
        }
    }

    private void StopReceiving()
    {
        Interlocked.Exchange(ref stopping, 1);
        foreach (nint handle in captureHandles)
        {
            if (closedHandles.ContainsKey(handle)) continue;
            if (!WinDivertNative.Shutdown(handle, 1))
            {
                failures.Enqueue(new Win32Exception(Marshal.GetLastPInvokeError(), "WinDivert receive shutdown failed."));
                CloseHandle(handle);
            }
        }
    }

    private void Cleanup()
    {
        StopReceiving();
        Task.WaitAll(workers.ToArray());
        foreach (nint handle in captureHandles.Where(handle => !closedHandles.ContainsKey(handle))) Drain(handle);
        foreach (nint handle in captureHandles.Append(sendHandle).Where(handle => handle != 0))
            CloseHandle(handle);
    }

    private void CloseHandle(nint handle)
    {
        if (closedHandles.TryAdd(handle, 0) && !WinDivertNative.Close(handle))
            failures.Enqueue(new Win32Exception(Marshal.GetLastPInvokeError(), "WinDivert close failed."));
    }

    private unsafe void Drain(nint handle)
    {
        byte[] packet = new byte[65575];
        fixed (byte* buffer = packet)
        {
            while (WinDivertNative.Receive(handle, buffer, (uint)packet.Length, out uint length, out WinDivertAddress address))
                if (!WinDivertNative.Send(handle, buffer, length, out uint sent, in address) || sent != length)
                    failures.Enqueue(new Win32Exception(Marshal.GetLastPInvokeError(), "WinDivert startup queue reinjection failed."));
            int error = Marshal.GetLastPInvokeError();
            if (error != 232) failures.Enqueue(new Win32Exception(error, "WinDivert startup queue drain failed."));
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            Cleanup();
            disposed = true;
            if (!failures.IsEmpty) throw new AggregateException("DNS interception cleanup encountered errors.", failures);
        }
    }
}
