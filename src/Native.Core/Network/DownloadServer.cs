using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FlymeNative.Core;

public sealed class DownloadServer : IAsyncDisposable
{
    public const string TargetHost = "carapp-a-res.flymeauto.com";
    private readonly string payloadPath;
    private readonly IPAddress address;
    private readonly int requestedHttpsPort;
    private readonly int requestedHttpPort;
    private readonly Action<string>? log;
    private readonly SemaphoreSlim lifecycle = new(1, 1);
    private readonly ConcurrentDictionary<long, Task> clients = new();
    private CancellationTokenSource? lifetime;
    private CancellationTokenRegistration cancellationRegistration;
    private TcpListener? https;
    private TcpListener? http;
    private X509Certificate2? certificate;
    private HttpClient? upstream;
    private Task[] acceptTasks = [];
    private long clientId;
    private bool disposed;

    public DownloadServer(string payloadPath, IPAddress address, int httpsPort = 443, int httpPort = 80, Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadPath);
        ArgumentNullException.ThrowIfNull(address);
        ArgumentOutOfRangeException.ThrowIfNegative(httpsPort);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(httpsPort, 65535);
        ArgumentOutOfRangeException.ThrowIfNegative(httpPort);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(httpPort, 65535);
        this.payloadPath = payloadPath;
        this.address = address;
        requestedHttpsPort = httpsPort;
        requestedHttpPort = httpPort;
        this.log = log;
    }

    public int HttpsPort { get; private set; }
    public int HttpPort { get; private set; }

    public void CheckHealth()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (lifetime is null || lifetime.IsCancellationRequested)
            throw new InvalidOperationException("下载监听服务未运行。");
        foreach (Task accept in acceptTasks)
            if (accept.IsCompleted)
                throw new InvalidOperationException("下载连接接收循环已退出。", accept.Exception);
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        var initializing = false;
        try
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (lifetime is not null) throw new InvalidOperationException("Download server is already started.");
            initializing = true;
            var payload = await File.ReadAllBytesAsync(payloadPath, cancellationToken).ConfigureAwait(false);
            if (payload.Length == 0) throw new InvalidDataException("APK payload must contain at least one byte.");
            var snapshot = new DownloadPayload(payload);
            certificate = CreateCertificate();
            upstream = new HttpClient(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseProxy = false,
                UseCookies = false,
                ConnectTimeout = TimeSpan.FromSeconds(10)
            }) { Timeout = TimeSpan.FromSeconds(60) };
            lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            https = new TcpListener(address, requestedHttpsPort);
            http = new TcpListener(address, requestedHttpPort);
            https.Start();
            HttpsPort = ((IPEndPoint)https.LocalEndpoint).Port;
            http.Start();
            HttpPort = ((IPEndPoint)http.LocalEndpoint).Port;
            cancellationToken.ThrowIfCancellationRequested();
            cancellationRegistration = lifetime.Token.Register(() => { https.Stop(); http.Stop(); });
            acceptTasks = [AcceptAsync(https, true, snapshot), AcceptAsync(http, false, snapshot)];
            Log($"[监听就绪] HTTPS={address}:{HttpsPort}; HTTP={address}:{HttpPort}; APK={Path.GetFileName(payloadPath)}; 字节={payload.Length}; SHA256={Convert.ToHexString(SHA256.HashData(payload))}");
        }
        catch when (initializing)
        {
            await CleanupAsync().ConfigureAwait(false);
            throw;
        }
        finally { lifecycle.Release(); }
    }

    public async Task StopAsync()
    {
        await lifecycle.WaitAsync().ConfigureAwait(false);
        try { await CleanupAsync().ConfigureAwait(false); }
        finally { lifecycle.Release(); }
    }

    private async Task CleanupAsync()
    {
        if (lifetime is not null) await lifetime.CancelAsync().ConfigureAwait(false);
        https?.Stop();
        http?.Stop();
        await Task.WhenAll(acceptTasks).ConfigureAwait(false);
        await Task.WhenAll(clients.Values).ConfigureAwait(false);
        clients.Clear();
        acceptTasks = [];
        cancellationRegistration.Dispose();
        certificate?.Dispose();
        upstream?.Dispose();
        lifetime?.Dispose();
        lifetime = null;
        certificate = null;
        upstream = null;
    }

    private async Task AcceptAsync(TcpListener listener, bool secure, DownloadPayload snapshot)
    {
        var token = lifetime!.Token;
        try
        {
            while (true)
            {
                var client = await listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
                var id = Interlocked.Increment(ref clientId);
                Log($"[TCP到达] id={id}; client={client.Client.RemoteEndPoint}; local={client.Client.LocalEndPoint}; TLS={secure}");
                var task = ServeAsync(client, secure, snapshot);
                clients[id] = task;
                _ = task.ContinueWith(_ => clients.TryRemove(id, out var removed), CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (SocketException) when (token.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (token.IsCancellationRequested) { }
        catch (InvalidOperationException) when (token.IsCancellationRequested) { }
        catch (Exception error)
        {
            Log($"[监听失败] local={listener.LocalEndpoint}; {error}");
            throw;
        }
    }

    private async Task ServeAsync(TcpClient client, bool secure, DownloadPayload snapshot)
    {
        string peer = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        string stage = "连接建立";
        void ConnectionLog(string message) => Log($"[client={peer}] {message}");
        using (client)
        using (var transfer = CancellationTokenSource.CreateLinkedTokenSource(lifetime!.Token))
        using (var closeOnCancellation = transfer.Token.Register(client.Dispose))
        {
            transfer.CancelAfter(TimeSpan.FromMinutes(2));
            try
            {
                using Stream stream = secure ? new SslStream(client.GetStream(), false) : client.GetStream();
                if (stream is SslStream tls)
                {
                    stage = "TLS握手";
                    ConnectionLog("[TLS开始] 等待ClientHello，超时10秒；支持TLS1.2/1.3，ALPN=http/1.1");
                    using var handshake = CancellationTokenSource.CreateLinkedTokenSource(transfer.Token);
                    handshake.CancelAfter(TimeSpan.FromSeconds(10));
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        ApplicationProtocols = [SslApplicationProtocol.Http11],
                        ClientCertificateRequired = false
                    }, handshake.Token).ConfigureAwait(false);
                    ConnectionLog($"[TLS成功] version={tls.SslProtocol}; ALPN={tls.NegotiatedApplicationProtocol}; cipher={tls.NegotiatedCipherSuite}");
                }
                stage = "读取HTTP请求头";
                ConnectionLog("[HTTP等待] 等待请求头，超时10秒");
                DownloadRequest request;
                try { request = await DownloadRequest.ReadAsync(stream, transfer.Token).ConfigureAwait(false); }
                catch (DownloadProtocolException error)
                {
                    ConnectionLog($"[HTTP拒绝] status={error.Status}; 请求格式无效");
                    await DownloadResponse.EmptyAsync(stream, error.Status, transfer.Token).ConfigureAwait(false);
                    return;
                }
                ConnectionLog($"[HTTP请求] method={request.Method}; host={request.Headers.GetValueOrDefault("Host")}; path={request.Uri.AbsolutePath}; Range={request.Headers.GetValueOrDefault("Range") ?? "无"}");
                stage = "发送HTTP响应";
                if (!request.IsTargetHost)
                    await DownloadResponse.EmptyAsync(stream, 421, transfer.Token).ConfigureAwait(false);
                else if (request.IsApk)
                    await snapshot.SendAsync(stream, request, transfer.Token, ConnectionLog).ConfigureAwait(false);
                else
                    await DownloadProxy.SendAsync(upstream!, stream, request, secure, transfer.Token, ConnectionLog).ConfigureAwait(false);
                ConnectionLog("[连接处理完成]");
            }
            catch (Exception error) when (error is IOException or SocketException or AuthenticationException or OperationCanceledException or ObjectDisposedException or HttpRequestException)
            {
                ConnectionLog($"[连接失败] stage={stage}; {error}");
            }
        }
    }

    // A UI logger must not be able to interrupt socket cleanup or the accept loop.
    private void Log(string message)
    {
        try { log?.Invoke(message); }
        catch (Exception) { /* Logging is an external callback; transport owns its lifetime. */ }
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={TargetHost}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(TargetHost);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
        // Schannel server authentication needs a persisted key container on Windows.
        return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.UserKeySet);
    }

    public async ValueTask DisposeAsync()
    {
        await lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            if (disposed) return;
            disposed = true;
            await CleanupAsync().ConfigureAwait(false);
        }
        finally { lifecycle.Release(); }
    }
}
