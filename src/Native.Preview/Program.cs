using Avalonia;
using Avalonia.Headless;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using Avalonia.Input;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using FlymeNative.Desktop;

namespace FlymeNative.Preview;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            string output = Path.GetFullPath(args.Length == 1 ? args[0] : "previews");
            Directory.CreateDirectory(output);
            AppBuilder.Configure<App>().UseSkia()
                .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
                .SetupWithoutStarting();
            foreach (var (width, height) in new[] { (1000, 760), (760, 650) })
            foreach (var (name, theme) in new[] { ("light", ThemeVariant.Light), ("dark", ThemeVariant.Dark) })
            {
                var window = new ShellWindow(inspectEnvironment: false)
                {
                    Width = width, Height = height, RequestedThemeVariant = theme
                };
                window.Show();
                Dispatcher.UIThread.RunJobs();
                AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                Dispatcher.UIThread.RunJobs();
                var controls = window.GetVisualDescendants().OfType<Control>().ToArray();
                var inputs = controls.OfType<TextBox>().ToArray();
                var sizeInput = inputs.Single(input => AutomationProperties.GetName(input) == "目标大小，字节");
                inputs.Single(input => AutomationProperties.GetName(input) == "运行日志").Text =
                    "请选择 APK，确认目标字节数后开始服务。\n启动后让车机重连电脑热点，再重新下载同一商店入口。\n本机自检可验证 HTTPS 下载字节数与 SHA-256。";
                var mode = controls.OfType<CheckBox>().Single(check => AutomationProperties.GetName(check) == "原样观察模式");
                if (mode.IsChecked == true) throw new InvalidOperationException("替换模式应为初始模式。");
                mode.IsChecked = true;
                Dispatcher.UIThread.RunJobs();
                var reinject = controls.OfType<CheckBox>().Single(check => AutomationProperties.GetName(check) == "原包回注对照");
                if (!reinject.IsEnabled) throw new InvalidOperationException("原样观察模式应允许原包回注对照。");
                reinject.IsChecked = true;
                if (sizeInput.IsEnabled || inputs.Single(input => AutomationProperties.GetName(input) == "APK 文件路径").IsEnabled ||
                    controls.OfType<Button>().Single(button => Equals(button.Content, "本机自检")).IsEnabled)
                    throw new InvalidOperationException("原样观察必须禁用APK输入及自检。");
                mode.IsChecked = false;
                Dispatcher.UIThread.RunJobs();
                if (reinject.IsEnabled) throw new InvalidOperationException("替换模式不允许混入原包回注。");
                reinject.IsChecked = false;
                if (sizeInput.Text != "27233004" || sizeInput.IsReadOnly || !sizeInput.IsEnabled)
                    throw new InvalidOperationException("目标大小须默认 27233004 且可编辑。");
                if (!sizeInput.Focus()) throw new InvalidOperationException("目标大小输入无法获取焦点。");
                sizeInput.SelectAll();
                sizeInput.RaiseEvent(new TextInputEventArgs { RoutedEvent = InputElement.TextInputEvent, Text = "27233005" });
                if (sizeInput.Text != "27233005") throw new InvalidOperationException("目标大小编辑未生效。");
                sizeInput.SelectAll();
                sizeInput.RaiseEvent(new TextInputEventArgs { RoutedEvent = InputElement.TextInputEvent, Text = "27233004" });
                if (sizeInput.Text != "27233004") throw new InvalidOperationException("目标大小默认值未恢复。");
                controls.OfType<Button>().Single(button => Equals(button.Content, "开始服务")).Focus();
                Dispatcher.UIThread.RunJobs();
                AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                Dispatcher.UIThread.RunJobs();
                using var frame = window.CaptureRenderedFrame() ?? throw new InvalidOperationException("Avalonia 未产生渲染帧。");
                if (frame.PixelSize.Width != width || frame.PixelSize.Height != height)
                    throw new InvalidOperationException($"Unexpected frame size: {frame.PixelSize}");
                var file = Path.Combine(output, $"shell-{width}x{height}-{name}.png");
                frame.Save(file); Console.WriteLine(file);
                var start = controls.OfType<Button>().Single(button => Equals(button.Content, "开始服务"));
                var initialBounds = start.Bounds;
                start.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Dispatcher.UIThread.RunJobs();
                var log = inputs.Single(input => AutomationProperties.GetName(input) == "运行日志");
                if (log.Text?.Contains("请先选择 APK 文件。", StringComparison.Ordinal) != true)
                    throw new InvalidOperationException("空输入未显示验证错误。");
                if (start.Bounds != initialBounds) throw new InvalidOperationException("错误状态改变了主操作尺寸。");
                if (controls.OfType<Button>().Where(button => button.Content is string caption &&
                    caption is "开始服务" or "本机自检" or "刷新环境" or "选择 APK" or "打开诊断目录").Any(button => button.Bounds.Height < 24))
                    throw new InvalidOperationException("按钮目标高度不足。");
                if (!sizeInput.Focus()) throw new InvalidOperationException("目标大小输入无法获取焦点。");
                Console.WriteLine($"PASS: {name} {width}x{height}: default 27233004, editable, blank APK validation, stable button, target size, input focus");
                window.Close(); PumpUntil(() => !window.IsVisible, TimeSpan.FromSeconds(10));
            }
            SimulateSelfTest(output);
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }

    private static void PumpUntil(Func<bool> completed, TimeSpan timeout)
    {
        var elapsed = Stopwatch.StartNew();
        var frame = new DispatcherFrame();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(10) };
        timer.Tick += (_, _) =>
        {
            if (completed() || elapsed.Elapsed >= timeout) frame.Continue = false;
        };
        timer.Start();
        try { Dispatcher.UIThread.PushFrame(frame); }
        finally { timer.Stop(); }
        if (!completed()) throw new TimeoutException($"GUI operation exceeded {timeout}.");
    }

    private static void SimulateSelfTest(string output)
    {
        var steps = new List<string>();
        string receipt = Path.Combine(output, "gui-simulation.json");
        bool success = false;
        string? failure = null, reportPath = null, expectedHash = null;
        string? reportJson = null;
        var window = new ShellWindow(inspectEnvironment: false);
        try
        {
            string payload = Path.Combine(output, "download-fixture.apk");
            File.WriteAllBytes(payload, RandomNumberGenerator.GetBytes(27233004));
            using (var input = File.OpenRead(payload))
            {
                if (input.Length != 27233004) throw new InvalidDataException("Verified APK must contain 27233004 bytes.");
                expectedHash = Convert.ToHexString(SHA256.HashData(input));
            }
            steps.Add("Verified selected APK length 27233004 and computed its SHA-256: " + payload);
            window.Show(); Dispatcher.UIThread.RunJobs();
            var controls = window.GetVisualDescendants().OfType<Control>().ToArray();
            var apk = controls.OfType<TextBox>().Single(input => AutomationProperties.GetName(input) == "APK 文件路径");
            var log = controls.OfType<TextBox>().Single(input => AutomationProperties.GetName(input) == "运行日志");
            var button = controls.OfType<Button>().Single(control => Equals(control.Content, "本机自检"));
            apk.Text = payload;
            steps.Add("Set real ShellWindow APK input by AutomationProperties.Name.");
            var point = button.TranslatePoint(new Point(button.Bounds.Width / 2, button.Bounds.Height / 2), window)
                ?? throw new InvalidOperationException("Self-test button has no window coordinates.");
            var started = DateTime.UtcNow;
            window.MouseDown(point, MouseButton.Left);
            window.MouseUp(point, MouseButton.Left);
            if (button.IsEnabled || apk.IsEnabled) throw new InvalidOperationException("Self-test did not enter busy state.");
            steps.Add("Clicked 本机自检 through headless mouse input; verified busy controls.");
            PumpUntil(() => button.IsEnabled, TimeSpan.FromSeconds(150));
            string text = log.Text ?? "";
            const string reportMarker = "本机下载字节数与 SHA-256 一致。报告：";
            int marker = text.IndexOf(reportMarker, StringComparison.Ordinal);
            if (marker < 0 || !controls.OfType<TextBlock>().Any(block => block.Text == "本机自检通过"))
                throw new InvalidOperationException("GUI self-test failed: " + text);
            reportPath = text[(marker + reportMarker.Length)..].Split('\n')[0].Trim();
            if (File.GetLastWriteTimeUtc(reportPath) < started.AddSeconds(-2))
                throw new InvalidDataException("GUI report predates this click.");
            reportJson = File.ReadAllText(reportPath);
            using var report = JsonDocument.Parse(reportJson);
            var root = report.RootElement;
            if (!root.GetProperty("success").GetBoolean() || root.GetProperty("hardwareTested").GetBoolean() ||
                root.GetProperty("receivedBytes").GetInt64() != 27233004 ||
                !string.Equals(root.GetProperty("sha256").GetString(), expectedHash, StringComparison.OrdinalIgnoreCase) ||
                root.GetProperty("httpsPort").GetInt32() <= 0 || root.GetProperty("httpPort").GetInt32() <= 0)
                throw new InvalidDataException("Actual GUI report did not match the selected APK and real download server.");
            File.WriteAllText(Path.Combine(output, "gui-selftest-report.json"), reportJson);
            steps.Add("Pumped dispatcher until completion within 150 seconds; GUI status and success log verified.");
            steps.Add("Parsed newly generated GUI report: success=true, receivedBytes=27233004, SHA-256 matches selected APK, hardwareTested=false.");
            success = true;
        }
        catch (Exception error) { failure = error.ToString(); throw; }
        finally
        {
            window.Close();
            PumpUntil(() => !window.IsVisible, TimeSpan.FromSeconds(150));
            steps.Add("Closed actual ShellWindow and pumped dispatcher through resource cleanup.");
            using var stream = File.Create(receipt);
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
            writer.WriteStartObject();
            writer.WriteString("test", "actual-shell-window-local-https-selftest");
            writer.WriteBoolean("success", success);
            writer.WriteBoolean("hardwareTested", false);
            writer.WriteString("selectedApkSha256", expectedHash);
            writer.WriteString("generatedReportPath", reportPath);
            writer.WriteString("error", failure);
            writer.WriteStartArray("steps");
            foreach (string step in steps) writer.WriteStringValue(step);
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        Console.WriteLine("PASS: real GUI loopback HTTPS simulation: " + receipt);
    }
}
