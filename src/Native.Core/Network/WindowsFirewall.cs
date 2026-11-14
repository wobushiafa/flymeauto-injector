using System.Diagnostics;

namespace FlymeNative.Core;

internal sealed class WindowsFirewall : IDisposable
{
    private readonly string name = $"FlymeNative-Downloads-{Guid.NewGuid():N}";
    private readonly object gate = new();
    private bool disposed;

    private WindowsFirewall() { }

    internal static WindowsFirewall Create(HotspotInfo hotspot)
    {
        var rule = new WindowsFirewall();
        try
        {
            Run(AddArguments(rule.name, hotspot));
            return rule;
        }
        catch (Exception addError)
        {
            try { rule.Dispose(); }
            catch (Exception cleanupError) { throw new AggregateException("Firewall creation and rollback failed.", addError, cleanupError); }
            throw;
        }
    }

    internal static string[] AddArguments(string name, HotspotInfo hotspot)
    {
        WindowsSubnet subnet = WindowsSubnet.From(hotspot);
        return ["advfirewall", "firewall", "add", "rule", $"name={name}", "dir=in", "action=allow",
            "enable=yes", "profile=any", "protocol=TCP", "localport=80,443", $"localip={hotspot.Address}",
            $"remoteip={WindowsSubnet.Format(subnet.Network)}/{hotspot.PrefixLength}", "edge=no"];
    }

    private static void Run(string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("Cannot launch netsh.exe.");
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException("Windows Firewall netsh operation timed out.");
        }
        Task.WaitAll(output, error);
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Windows Firewall netsh failed ({process.ExitCode}): {output.Result} {error.Result}");
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            Run(["advfirewall", "firewall", "delete", "rule", $"name={name}"]);
            disposed = true;
        }
    }
}
