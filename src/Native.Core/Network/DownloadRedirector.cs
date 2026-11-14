using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace FlymeNative.Core;

public sealed class DownloadRedirector : IDisposable
{
    private readonly HotspotInfo hotspot;
    private readonly IPAddress publicAddress;
    private readonly Action<string> log;
    private readonly DownloadRouteTable routes;
    private readonly List<nint> handles = [];
    private readonly List<Task> workers = [];
    private readonly ConcurrentQueue<Exception> failures = new();
    private readonly ConcurrentDictionary<nint, byte> closedHandles = new();
    private int stopping;
    private bool attempted, disposed;

    public DownloadRedirector(HotspotInfo hotspot, IPAddress publicAddress, Action<string> log)
    {
        if (!DownloadRouteTable.IsPublic(publicAddress)) throw new ArgumentException("下载转接需要公网IPv4地址。", nameof(publicAddress));
        this.hotspot = hotspot;
        this.publicAddress = publicAddress;
        this.log = log;
        routes = new(hotspot, publicAddress);
    }

    public void AuthorizeClient(IPAddress client) => routes.Authorize(client);

    public static async Task<IPAddress> ResolveAddressAsync(CancellationToken token)
    {
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(DownloadServer.TargetHost,
            System.Net.Sockets.AddressFamily.InterNetwork, token).WaitAsync(TimeSpan.FromSeconds(10), token).ConfigureAwait(false);
        return addresses.FirstOrDefault(DownloadRouteTable.IsPublic) ??
            throw new InvalidOperationException("下载域名未解析到可用公网IPv4，请检查网络、代理和系统DNS后重试。");
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (attempted) throw new InvalidOperationException("下载转接不可重复启动。");
        attempted = true;
        if (!OperatingSystem.IsWindows() || !WindowsNetwork.IsAdministrator) throw new InvalidOperationException("下载转接需要Windows管理员权限。");
        try
        {
            var subnet = WindowsSubnet.From(hotspot);
            string clients = $"ip.SrcAddr > {WindowsSubnet.Format(subnet.Network)} and ip.SrcAddr < {WindowsSubnet.Format(subnet.Broadcast)} and ip.SrcAddr != {hotspot.Address}";
            string forward = $"ip and tcp and !impostor and {clients} and ip.DstAddr == {publicAddress} and (tcp.DstPort == 80 or tcp.DstPort == 443)";
            string reverse = $"outbound and ip and tcp and ip.SrcAddr == {hotspot.Address} and ip.DstAddr > {WindowsSubnet.Format(subnet.Network)} and ip.DstAddr < {WindowsSubnet.Format(subnet.Broadcast)} and (tcp.SrcPort == 80 or tcp.SrcPort == 443)";
            handles.Add(WinDivertNative.OpenChecked(forward, 1, 0));
            handles.Add(WinDivertNative.OpenChecked(reverse, 0, 0));
            workers.Add(Task.Factory.StartNew(() => Run(handles[0], handles[1], false), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default));
            workers.Add(Task.Factory.StartNew(() => Run(handles[1], handles[1], true), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default));
            log($"[下载转接就绪] CDN={publicAddress}; 本机={hotspot.Address}; 端口=80/443；仅接管收到目标DNS回答的热点客户端新连接");
            CheckHealth();
        }
        catch { Dispose(); throw; }
    }

    public void CheckHealth()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (!failures.IsEmpty) throw new AggregateException("下载转接失败。", failures);
        if (!attempted || workers.Count != 2 || workers.Any(worker => worker.IsCompleted)) throw new InvalidOperationException("下载转接未运行。");
    }

    private unsafe void Run(nint capture, nint injector, bool returning)
    {
        try
        {
            byte[] packet = new byte[65575];
            fixed (byte* buffer = packet)
            {
                while (WinDivertNative.Receive(capture, buffer, (uint)packet.Length, out uint length, out WinDivertAddress address))
                {
                    var bytes = packet.AsSpan(0, checked((int)length));
                    bool translated = routes.Translate(bytes, returning);
                    nint send = capture;
                    if (translated)
                    {
                        send = injector;
                        if (!returning) address = new() { InterfaceIndex = (uint)hotspot.InterfaceIndex };
                        if (!WinDivertNative.CalculateChecksums(buffer, length, ref address, 0)) throw new InvalidOperationException("TCP校验和计算失败。");
                    }
                    if (!WinDivertNative.Send(send, buffer, length, out uint sent, in address) || sent != length)
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "下载连接回注失败。");
                    int ihl = (packet[0] & 15) * 4;
                    if (translated && length >= ihl + 20 && (packet[ihl + 13] & 2) != 0)
                        log($"[下载连接转接] direction={(returning ? "返回车机" : "进入本机")}; {new IPAddress(bytes.Slice(12, 4))} -> {new IPAddress(bytes.Slice(16, 4))}; CDN={publicAddress}");
                }
                int error = Marshal.GetLastPInvokeError();
                if (error != 232 || Volatile.Read(ref stopping) == 0) throw new Win32Exception(error, "下载转接接收失败。");
            }
        }
        catch (Exception error)
        {
            failures.Enqueue(error);
            log("[下载转接线程失败] " + error);
            StopReceiving();
        }
    }

    private void StopReceiving()
    {
        if (Interlocked.Exchange(ref stopping, 1) != 0) return;
        foreach (nint handle in handles)
            if (!WinDivertNative.Shutdown(handle, 1))
            {
                failures.Enqueue(new Win32Exception(Marshal.GetLastPInvokeError(), "下载转接停止接收失败。"));
                if (closedHandles.TryAdd(handle, 0)) WinDivertNative.Close(handle); // Unblock the worker even if shutdown failed.
            }
    }

    public void Dispose()
    {
        if (disposed) return;
        StopReceiving();
        Task.WaitAll(workers.ToArray());
        foreach (nint handle in handles)
            if (closedHandles.TryAdd(handle, 0) && !WinDivertNative.Close(handle)) failures.Enqueue(new Win32Exception(Marshal.GetLastPInvokeError(), "下载转接句柄关闭失败。"));
        disposed = true;
        if (!failures.IsEmpty) throw new AggregateException("下载转接清理失败。", failures);
    }
}
