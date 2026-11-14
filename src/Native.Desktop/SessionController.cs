using FlymeNative.Core;

namespace FlymeNative.Desktop;

/// <summary>Serialized by the shell; all expensive work and disposal run off the UI thread.</summary>
public sealed class SessionController(Action<string> log, string? diagnosticDirectory = null)
{
    private IDisposable? firewall;
    private DownloadServer? download;
    private DnsInterceptor? dns;
    private DownloadRedirector? redirect;
    private TrafficObserver? observer;
    private NicCapture? nicCapture;
    private string? sessionDirectory;

    public bool IsRunning { get; private set; }
    public bool HasResources => nicCapture is not null || observer is not null || dns is not null || redirect is not null || download is not null || firewall is not null || sessionDirectory is not null;
    public int DnsHits => dns?.Hits ?? 0;

    public async Task StartObservationAsync(CancellationToken token, bool reinjectOriginal = false)
    {
        if (HasResources) throw new InvalidOperationException("请先停止当前服务再切换模式。");
        try
        {
            token.ThrowIfCancellationRequested();
            if (!WindowsNetwork.IsAdministrator) throw new InvalidOperationException("原样观察需要管理员权限。");
            var hotspot = WindowsNetwork.DiscoverHotspot();
            log($"[模式] {(reinjectOriginal ? "DNS原包回注对照" : "原样观察") }；热点={hotspot.Name} {hotspot.Address}；不加工APK、不改DNS答案、不启动本地下载监听、不设置防火墙");
            await StartCaptureAsync(hotspot, reinjectOriginal ? "reinjection-control" : "observation").ConfigureAwait(false);
            if (reinjectOriginal)
            {
                dns = new DnsInterceptor(hotspot, log, rewriteAnswers: false);
                dns.Start();
                dns.CheckHealth();
            }
            token.ThrowIfCancellationRequested();
            IsRunning = true;
            log("[观察已启动] 请在车机触发同一商店入口正常下载；停止后可切换脚本替换。");
        }
        catch
        {
            await StopAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task StartCaptureAsync(HotspotInfo hotspot, string mode)
    {
        string root = diagnosticDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FlymeNative", "logs");
        string folder = Path.Combine(root, $"session-{mode}-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}");
        nicCapture = new NicCapture(folder, log);
        try { await nicCapture.StartAsync().ConfigureAwait(false); }
        catch (Exception error) { log("[网卡抓包不可用] " + error); }
        observer = new TrafficObserver(hotspot, log);
        observer.Start();
    }

    public async Task StartAsync(string source, long bytes, CancellationToken token)
    {
        if (HasResources)
            throw new InvalidOperationException("服务尚未完全停止，请先停止服务或关闭窗口以重试清理。");
        try
        {
            token.ThrowIfCancellationRequested();
            if (!WindowsNetwork.IsAdministrator) throw new InvalidOperationException("请以管理员身份重新打开程序，再启动服务。");
            var hotspot = WindowsNetwork.DiscoverHotspot();
            log("[模式] APK替换；目标域名返回公网地址，下载连接透明转接至本机");
            log($"已确认热点：{hotspot.Name} · {hotspot.Address}/{hotspot.PrefixLength}");
            var publicAddress = await DownloadRedirector.ResolveAddressAsync(token).ConfigureAwait(false);
            log($"[下载域名解析] {DownloadServer.TargetHost} -> {publicAddress}；仅用于本次会话，无固定CDN地址");
            token.ThrowIfCancellationRequested();
            sessionDirectory = Path.Combine(Path.GetTempPath(), "FlymeNative", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(sessionDirectory);
            var result = ApkBuilder.Build(source, Path.Combine(sessionDirectory, "payload.apk"), bytes, log);
            log($"APK 已准备：{result.Length:N0} 字节；SHA-256 {result.Sha256}");
            token.ThrowIfCancellationRequested();
            firewall = WindowsNetwork.AllowDownloads(hotspot);
            download = new DownloadServer(result.Path, hotspot.Address, log: log);
            await download.StartAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            redirect = new DownloadRedirector(hotspot, publicAddress, log);
            redirect.Start();
            await StartCaptureAsync(hotspot, "replacement").ConfigureAwait(false);
            dns = new DnsInterceptor(hotspot, log, downloadAddress: publicAddress, answered: redirect.AuthorizeClient);
            dns.Start();
            dns.CheckHealth();
            token.ThrowIfCancellationRequested();
            IsRunning = true;
            log("服务已启动。请让车机重新连接热点后下载；已有DNS缓存或下载连接不会强行接管。支持断点续传，安装结果以车机为准。");
        }
        catch (Exception startError)
        {
            try { await StopAsync().ConfigureAwait(false); }
            catch (Exception cleanupError) { throw new AggregateException(startError, cleanupError); }
            throw;
        }
    }

    public void CheckHealth()
    {
        dns?.CheckHealth();
        redirect?.CheckHealth();
        download?.CheckHealth();
        observer?.CheckHealth();
    }

    public async Task StopAsync()
    {
        IsRunning = false;
        List<Exception> errors = [];
        if (nicCapture is not null)
        {
            try { await nicCapture.DisposeAsync().ConfigureAwait(false); nicCapture = null; }
            catch (Exception error) { errors.Add(error); log("网卡抓包清理失败：" + error); }
        }
        // Continue through every cleanup stage even when an earlier resource fails to release.
        if (observer is not null)
        {
            try { observer.Dispose(); observer = null; }
            catch (Exception error) { errors.Add(error); log("网络观测清理失败：" + error); }
        }
        if (dns is not null)
        {
            var current = dns;
            try { current.Dispose(); dns = null; } catch (Exception error) { errors.Add(error); log("DNS 清理失败：" + error.Message); }
        }
        if (download is not null)
        {
            var current = download;
            try { await current.DisposeAsync().ConfigureAwait(false); download = null; }
            catch (Exception error) { errors.Add(error); log("下载服务清理失败：" + error.Message); }
        }
        if (redirect is not null)
        {
            var current = redirect;
            try { current.Dispose(); redirect = null; } catch (Exception error) { errors.Add(error); log("下载转接清理失败：" + error.Message); }
        }
        if (firewall is not null)
        {
            var current = firewall;
            try { current.Dispose(); firewall = null; } catch (Exception error) { errors.Add(error); log("防火墙清理失败：" + error.Message); }
        }
        if (sessionDirectory is not null)
        {
            var directory = sessionDirectory;
            try { Directory.Delete(directory, true); sessionDirectory = null; } catch (Exception error) { errors.Add(error); log("临时 APK 清理失败：" + error.Message); }
        }
        if (errors.Count != 0) throw new AggregateException("资源清理未全部成功，请查看日志。", errors);
    }
}
