using Avalonia;
using FlymeNative.Core;
using System.Globalization;

namespace FlymeNative.Desktop;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length != 0) return RunCommandAsync(args).GetAwaiter().GetResult();
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UsePlatformDetect();

    private static async Task<int> RunCommandAsync(string[] args)
    {
        try
        {
            switch (args)
            {
                case ["--selftest", var payload, var report]:
                    await DownloadSelfTest.RunAsync(payload, report).ConfigureAwait(false);
                    return 0;
                case ["--prepare", var source, var output, var bytes]:
                    if (!long.TryParse(bytes, NumberStyles.None, CultureInfo.InvariantCulture, out var size))
                        throw new ArgumentException("目标大小必须是整数个字节。");
                    var result = await Task.Run(() => ApkBuilder.Build(source, output, size)).ConfigureAwait(false);
                    Console.WriteLine($"{result.Path}\n{result.Length}\n{result.Sha256}");
                    return 0;
                default:
                    Console.Error.WriteLine("用法：--selftest <payload> <report> 或 --prepare <source> <output> <bytes>");
                    return 2;
            }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
    }
}
