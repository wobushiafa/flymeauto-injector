using System.Text;

namespace FlymeNative.Desktop;

internal sealed class SessionLog : IDisposable
{
    private readonly object gate = new();
    private readonly StreamWriter writer;

    public SessionLog()
    {
        string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FlymeNative", "logs",
            $"session-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        FilePath = Path.Combine(directory, "session.log");
        writer = new StreamWriter(new FileStream(FilePath, FileMode.CreateNew, FileAccess.Write, FileShare.Read), new UTF8Encoding(false))
        {
            AutoFlush = true
        };
        Write($"FlymeNative 1.0.9 Debug 回注对照版；PID={Environment.ProcessId}；日志文件={FilePath}");
    }

    public string FilePath { get; }

    public string Write(string message)
    {
        string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";
        lock (gate) writer.WriteLine(line);
        return line;
    }

    public void Dispose()
    {
        lock (gate) writer.Dispose();
    }
}
