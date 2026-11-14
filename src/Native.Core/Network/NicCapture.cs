using System.Diagnostics;
using System.IO.Compression;
using System.Text;

namespace FlymeNative.Core;

/// <summary>Owns only the pktmon session it successfully started; never changes global filters.</summary>
public sealed class NicCapture(string directory, Action<string> log) : IAsyncDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly CancellationTokenSource deadline = new();
    private Task? automaticStop;
    private string? etl;
    private bool owned;

    public async Task StartAsync()
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (etl is not null) throw new InvalidOperationException("网卡抓包只能启动一次。");
            Directory.CreateDirectory(directory);
            etl = Path.Combine(directory, $"nic-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.etl");
            await RunAsync(["start", "--capture", "--pkt-size", "768", "--file-size", "32", "--log-mode", "circular", "--file-name", etl]).ConfigureAwait(false);
            owned = true;
            log($"[网卡抓包启动] Windows PktMon；全网络栈（含NIC与丢包路径）；每包前768字节；循环上限32MB；60秒自动停止导出；文件={etl}；包含网络元数据，请仅用于本次排障");
            try { await RunAsync(["filter", "list"]).ConfigureAwait(false); }
            catch (Exception error) when (error is IOException or InvalidOperationException or TimeoutException)
            { log("[抓包过滤器诊断失败] " + error.Message); }
            automaticStop = StopAfterDeadlineAsync();
        }
        finally { gate.Release(); }
    }

    private async Task StopAfterDeadlineAsync()
    {
        try { await Task.Delay(TimeSpan.FromSeconds(60), deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested) { return; }
        try { await StopAsync().ConfigureAwait(false); }
        catch (Exception error) { log("[网卡抓包自动导出失败] " + error); }
    }

    public async Task StopAsync()
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!owned) return;
            await RunAsync(["stop"]).ConfigureAwait(false);
            owned = false;
            string pcap = Path.ChangeExtension(etl!, ".pcapng");
            await RunAsync(["etl2pcap", etl!, "--out", pcap]).ConfigureAwait(false);
            log($"[网卡抓包导出完成] {pcap}；这是真实网卡层记录，仍需分析是否发出目标DNS回应");
            try { NicDnsAudit.Summarize(pcap, log); }
            catch (Exception error) when (error is InvalidDataException or EndOfStreamException or IOException)
            { log("[NIC自动分析未完成] 原始pcapng已保留；" + error.Message); }
            await RunAsync(["etl2txt", etl!, "--out", Path.ChangeExtension(etl!, ".txt")]).ConfigureAwait(false);
            if (Path.GetFileName(directory).StartsWith("session-", StringComparison.Ordinal))
            {
                string archive = directory + "-diagnostics.zip";
                using (var bundle = ZipFile.Open(archive, ZipArchiveMode.Create))
                {
                    var sources = Directory.EnumerateFiles(directory).ToList();
                    string? parent = Path.GetDirectoryName(directory);
                    if (!File.Exists(Path.Combine(directory, "session.log")) && parent is not null &&
                        File.Exists(Path.Combine(parent, "session.log"))) sources.Add(Path.Combine(parent, "session.log"));
                    foreach (string source in sources)
                    {
                        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var output = bundle.CreateEntry(Path.GetFileName(source), CompressionLevel.Fastest).Open();
                        long remaining = input.Length;
                        byte[] buffer = new byte[65536];
                        while (remaining > 0)
                        {
                            int count = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(remaining, buffer.Length))).ConfigureAwait(false);
                            if (count == 0) break;
                            await output.WriteAsync(buffer.AsMemory(0, count)).ConfigureAwait(false);
                            remaining -= count;
                        }
                    }
                }
                log($"[诊断包已生成] {archive}；包含本次日志、ETL、pcapng和文本记录；请发这个ZIP");
            }
        }
        finally { gate.Release(); }
    }

    private async Task RunAsync(string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "pktmon.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        foreach (string value in arguments) start.ArgumentList.Add(value);
        using var process = Process.Start(start) ?? throw new IOException("无法启动Windows pktmon。");
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try { await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().ConfigureAwait(false);
            throw new TimeoutException("pktmon操作超过20秒：" + string.Join(' ', arguments));
        }
        string text = (await output.ConfigureAwait(false)) + (await error.ConfigureAwait(false));
        log($"[PktMon] command={arguments[0]}; exit={process.ExitCode}; {text.Trim()}");
        if (process.ExitCode != 0) throw new InvalidOperationException("pktmon操作失败：" + text.Trim());
    }

    public async ValueTask DisposeAsync()
    {
        await deadline.CancelAsync().ConfigureAwait(false);
        if (automaticStop is not null) await automaticStop.ConfigureAwait(false);
        await StopAsync().ConfigureAwait(false);
        deadline.Dispose();
    }
}
