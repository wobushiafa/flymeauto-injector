using System.Globalization;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using FlymeNative.Core;

namespace FlymeNative.Desktop;

public class FluentWindow : Window;

public sealed class ShellWindow : FluentWindow
{
    private readonly TextBox apkPath = new() { Watermark = "选择要准备的 APK 文件", MinHeight = 40 };
    private readonly TextBox targetBytes = new() { Text = "27233004", Watermark = "填写精确字节数", MinHeight = 40 };
    private readonly Button browse = ActionButton("选择 APK", 112);
    private readonly Button primary = ActionButton("开始服务", 144);
    private readonly Button selfTest = ActionButton("本机自检", 112);
    private readonly Button refresh = ActionButton("刷新环境", 112);
    private readonly Button openDiagnostics = ActionButton("打开诊断目录", 128);
    private readonly CheckBox observationMode = new() { Content = "原样观察（不替换下载）", MinHeight = 32 };
    private readonly CheckBox reinjectionControl = new() { Content = "DNS原包回注对照（不改答案）", MinHeight = 32, IsEnabled = false };
    private readonly TextBlock environment = Text("正在检查管理员与移动热点…");
    private readonly TextBlock status = Text("尚未启动");
    private readonly TextBlock hits = Text("DNS 命中：0");
    private readonly TextBox logs = new() { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, Height = 160, VerticalAlignment = VerticalAlignment.Top };
    private readonly ProgressBar progress = new() { IsIndeterminate = true, Height = 4, IsVisible = false };
    private readonly SessionController controller;
    private readonly SessionLog sessionLog = new();
    private readonly DispatcherTimer healthTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private Task operation = Task.CompletedTask;
    private CancellationTokenSource? cancellation;
    private bool busy, closing, mayClose;

    public ShellWindow(bool inspectEnvironment = true)
    {
        controller = new SessionController(AppendLog, Path.GetDirectoryName(sessionLog.FilePath));
        Title = "flymeauto-injector 1.1.0";
        Width = 1000; Height = 760; MinWidth = 760; MinHeight = 650;
        FontFamily = new FontFamily("Microsoft YaHei UI, Segoe UI");
        FontSize = 14;
        primary.Classes.Add("accent");
        AutomationProperties.SetName(apkPath, "APK 文件路径");
        AutomationProperties.SetName(targetBytes, "目标大小，字节");
        AutomationProperties.SetName(logs, "运行日志");
        AutomationProperties.SetName(observationMode, "原样观察模式");
        AutomationProperties.SetName(reinjectionControl, "原包回注对照");
        ScrollViewer.SetVerticalScrollBarVisibility(logs, Avalonia.Controls.Primitives.ScrollBarVisibility.Visible);
        ScrollViewer.SetHorizontalScrollBarVisibility(logs, Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled);
        Content = BuildContent();
        browse.Click += BrowseClick;
        primary.Click += PrimaryClick;
        selfTest.Click += SelfTestClick;
        refresh.Click += RefreshClick;
        observationMode.IsCheckedChanged += (_, _) => UpdateModeInputs();
        openDiagnostics.Click += (_, _) =>
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe")
                { UseShellExecute = true, Arguments = $"\"{Path.GetDirectoryName(sessionLog.FilePath)}\"" });
            }
            catch (Exception error) { ShowError(error); }
        };
        Closing += OnClosing;
        healthTimer.Tick += HealthTick;
        if (inspectEnvironment) Opened += async (_, _) => await RefreshEnvironmentAsync();
        else environment.Text = "预览模式：尚未检查管理员与移动热点";
        AppendLog("请选择 APK。目标大小默认 27233004 字节，请按商店下载入口的真实大小修改。自检仅验证所选 APK 的本机 HTTPS 下载。");
        AppendLog("完整日志文件：" + sessionLog.FilePath);
    }

    private Control BuildContent()
    {
        var root = new Grid { RowDefinitions = new("Auto,Auto,Auto,Auto,Auto,Auto"), Margin = new Thickness(16), RowSpacing = 8 };
        Add(root, new StackPanel { Spacing = 8, Children =
        {
            new TextBlock { Text = "APK 下载准备", FontSize = 26, FontWeight = FontWeight.SemiBold },
            Text("选择安装包，按目标字节数准备签名 APK，并在 Windows 移动热点上提供下载。")
        } }, 0);
        var inputs = new StackPanel { Spacing = 8 };
        inputs.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 16, Children = { observationMode, reinjectionControl } });
        var fields = new Grid { ColumnDefinitions = new("*,180"), ColumnSpacing = 12 };
        var apkField = new StackPanel { Spacing = 4 };
        apkField.Children.Add(Label("APK 文件"));
        var picker = new Grid { ColumnDefinitions = new("*,Auto"), ColumnSpacing = 12 };
        picker.Children.Add(apkPath); Grid.SetColumn(browse, 1); picker.Children.Add(browse);
        apkField.Children.Add(picker);
        fields.Children.Add(apkField);
        var sizeField = new StackPanel { Spacing = 4, Children = { Label("目标大小（字节）"), targetBytes } };
        Grid.SetColumn(sizeField, 1); fields.Children.Add(sizeField);
        inputs.Children.Add(fields);
        inputs.Children.Add(new TextBlock { Text = "默认 27233004 字节；请按商店下载入口的真实大小修改，准备后的 APK 将严格匹配该大小。", FontSize = 12, TextWrapping = TextWrapping.Wrap });
        Add(root, inputs, 1);
        var network = new Grid { ColumnDefinitions = new("*,Auto,Auto"), ColumnSpacing = 12 };
        network.Children.Add(environment); Grid.SetColumn(refresh, 1); network.Children.Add(refresh);
        Grid.SetColumn(openDiagnostics, 2); network.Children.Add(openDiagnostics);
        Add(root, network, 2);
        var actions = new Grid { ColumnDefinitions = new("Auto,Auto,*"), RowDefinitions = new("Auto,Auto"), ColumnSpacing = 12, RowSpacing = 8 };
        actions.Children.Add(primary); Grid.SetColumn(selfTest, 1); actions.Children.Add(selfTest);
        status.VerticalAlignment = VerticalAlignment.Center; Grid.SetColumn(status, 2); actions.Children.Add(status);
        Grid.SetRow(progress, 1); Grid.SetColumnSpan(progress, 3); actions.Children.Add(progress);
        Add(root, actions, 3);
        var logRegion = new Grid { RowDefinitions = new("Auto,Auto"), RowSpacing = 8 };
        logRegion.Children.Add(new TextBlock { Text = "运行日志", FontSize = 18, FontWeight = FontWeight.SemiBold });
        Grid.SetRow(logs, 1); logRegion.Children.Add(logs); Add(root, logRegion, 4);
        var footer = new StackPanel { Spacing = 4, Children =
        {
            hits,
            new TextBlock { Text = "启动后请让车机重连热点再下载 · 支持断点续传 · 仅处理目标下载域名的 IPv4 UDP DNS 与 HTTP/HTTPS", FontSize = 12, TextWrapping = TextWrapping.Wrap }
        } };
        Add(root, footer, 5);
        return root;
    }

    private static TextBlock Text(string value) => new() { Text = value, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
    private static TextBlock Label(string value) => new() { Text = value, FontWeight = FontWeight.SemiBold };
    private static Button ActionButton(string caption, double width) => new() { Content = caption, Width = width, Height = 40, HorizontalContentAlignment = HorizontalAlignment.Center };
    private static void Add(Grid grid, Control control, int row) { Grid.SetRow(control, row); grid.Children.Add(control); }

    private async void BrowseClick(object? sender, RoutedEventArgs args)
    {
        try
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "选择 APK", AllowMultiple = false,
                FileTypeFilter = [new FilePickerFileType("Android 安装包") { Patterns = ["*.apk"] }]
            });
            if (!closing && files.Count == 1) apkPath.Text = files[0].TryGetLocalPath() ?? throw new IOException("请选择本机文件。");
        }
        catch (Exception error) { ShowError(error); }
    }

    private async void PrimaryClick(object? sender, RoutedEventArgs args)
    {
        if (closing) return;
        if (busy) { cancellation?.Cancel(); primary.IsEnabled = false; status.Text = "正在取消，等待当前步骤结束…"; return; }
        operation = controller.HasResources ? StopSessionAsync() : StartSessionAsync();
        await operation;
    }

    private async Task StartSessionAsync()
    {
        try
        {
            bool observe = observationMode.IsChecked == true;
            bool reinject = observe && reinjectionControl.IsChecked == true;
            string source = observe ? "" : ValidateSource();
            long bytes = 0;
            if (!observe && (!long.TryParse(targetBytes.Text, NumberStyles.None, CultureInfo.InvariantCulture, out bytes) || bytes <= 0 || bytes >= uint.MaxValue))
                throw new ArgumentException("目标大小须为 1 至 4,294,967,294 之间的整数字节数。");
            cancellation = new CancellationTokenSource();
            SetBusy(true); status.Text = "检查环境并准备 APK…"; primary.Content = "取消准备";
            await Task.Run(() => observe ? controller.StartObservationAsync(cancellation.Token, reinject) : controller.StartAsync(source, bytes, cancellation.Token));
            status.Text = observe ? (reinject ? "DNS原包回注中（无替换）" : "原样观察中（无替换）") : "脚本替换运行中"; healthTimer.Start();
        }
        catch (OperationCanceledException) { status.Text = "已取消"; AppendLog("操作已取消，资源已回收。"); }
        catch (Exception error) { ShowError(error); }
        finally { cancellation?.Dispose(); cancellation = null; SetBusy(false); }
    }

    private async Task StopSessionAsync()
    {
        healthTimer.Stop(); SetBusy(true); status.Text = "正在停止并回收资源…";
        try { await Task.Run(controller.StopAsync); status.Text = "已停止"; AppendLog("服务已停止，资源已回收。"); }
        catch (Exception error) { ShowError(error); }
        finally { SetBusy(false); }
    }

    private async void SelfTestClick(object? sender, RoutedEventArgs args)
    {
        if (busy || closing || controller.HasResources) return;
        operation = RunSelfTestAsync(); await operation;
    }

    private async Task RunSelfTestAsync()
    {
        try
        {
            var source = ValidateSource(); SetBusy(true); primary.IsEnabled = false; status.Text = "正在验证本机 HTTPS 下载…";
            var report = Path.Combine(Path.GetTempPath(), "flyme-selftest-" + Guid.NewGuid().ToString("N") + ".json");
            await Task.Run(() => DownloadSelfTest.RunAsync(source, report));
            status.Text = "本机自检通过"; AppendLog("本机下载字节数与 SHA-256 一致。报告：" + report);
        }
        catch (Exception error) { ShowError(error); }
        finally { SetBusy(false); }
    }

    private string ValidateSource()
    {
        if (string.IsNullOrWhiteSpace(apkPath.Text)) throw new ArgumentException("请先选择 APK 文件。");
        string source = Path.GetFullPath(apkPath.Text.Trim());
        if (!File.Exists(source) || !string.Equals(Path.GetExtension(source), ".apk", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("请选择存在的本机 APK 文件。");
        return source;
    }

    private async void RefreshClick(object? sender, RoutedEventArgs args) => await RefreshEnvironmentAsync();

    private async Task RefreshEnvironmentAsync()
    {
        refresh.IsEnabled = false;
        try
        {
            environment.Text = await Task.Run(() =>
            {
                string admin = WindowsNetwork.IsAdministrator ? "管理员：是" : "管理员：否（启动前需提升权限）";
                try { var hotspot = WindowsNetwork.DiscoverHotspot(); return $"{admin}\n热点：{hotspot.Name} · {hotspot.Address}/{hotspot.PrefixLength}"; }
                catch (Exception error)
                {
                    AppendLog("热点检查：" + error.Message);
                    return admin + "\n热点：未识别到唯一可用的 IPv4 移动热点，请开启或检查热点。";
                }
            });
        }
        catch (Exception error) { environment.Text = "环境检查失败：" + error.Message; AppendLog(environment.Text); }
        finally { refresh.IsEnabled = !busy && !closing; }
    }

    private async void HealthTick(object? sender, EventArgs args)
    {
        if (busy || closing) return;
        hits.Text = $"DNS 命中：{controller.DnsHits}";
        try { controller.CheckHealth(); }
        catch (Exception error) { ShowError(error); operation = StopSessionAsync(); await operation; status.Text = "DNS 故障，服务已停止；请查看日志"; }
    }

    private void SetBusy(bool value)
    {
        busy = value; progress.IsVisible = value;
        apkPath.IsEnabled = targetBytes.IsEnabled = browse.IsEnabled = !value && !controller.HasResources && !closing;
        selfTest.IsEnabled = !value && !controller.HasResources && !closing;
        refresh.IsEnabled = !value && !closing;
        primary.IsEnabled = !closing;
        primary.Content = controller.HasResources ? "停止服务" : "开始服务";
        UpdateModeInputs();
    }

    private void UpdateModeInputs()
    {
        bool idle = !busy && !closing && !controller.HasResources;
        bool replace = observationMode.IsChecked != true;
        observationMode.IsEnabled = idle;
        reinjectionControl.IsEnabled = idle && !replace;
        apkPath.IsEnabled = targetBytes.IsEnabled = browse.IsEnabled = selfTest.IsEnabled = idle && replace;
    }

    private void ShowError(Exception error) { status.Text = "操作失败，请查看日志"; AppendLog(error.ToString()); }

    private void AppendLog(string message)
    {
        string line;
        try { line = sessionLog.Write(message); }
        catch (IOException error) { line = $"[日志文件写入失败：{error.Message}] {message}"; }
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(() => DisplayLog(line)); return; }
        DisplayLog(line);
    }

    private void DisplayLog(string line)
    {
        string text = logs.Text ?? "";
        if (text.Length > 60000) text = text[^40000..];
        logs.Text = text + line + "\n";
        logs.CaretIndex = logs.Text.Length;
    }

    private async void OnClosing(object? sender, WindowClosingEventArgs args)
    {
        if (mayClose) return;
        args.Cancel = true;
        if (closing) return;
        closing = true; cancellation?.Cancel(); healthTimer.Stop(); SetBusy(true);
        status.Text = "正在关闭，等待资源清理…";
        await operation;
        try { await Task.Run(controller.StopAsync); }
        catch (Exception error) { ShowError(error); closing = false; SetBusy(false); return; }
        AppendLog("窗口关闭，服务清理完成。");
        mayClose = true; Close();
    }
}
