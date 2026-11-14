using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace FlymeNative.Core;

public static class DownloadSelfTest
{
    public static async Task RunAsync(string payloadPath, string reportPath)
    {
        long received = 0;
        string? sha256 = null;
        Exception? failure = null;
        int httpsPort = 0;
        int httpPort = 0;
        try
        {
            using var input = File.OpenRead(payloadPath);
            var expectedLength = input.Length;
            var expectedHash = await SHA256.HashDataAsync(input).ConfigureAwait(false);
            await using var server = new DownloadServer(payloadPath, IPAddress.Loopback, 0, 0);
            await server.StartAsync().ConfigureAwait(false);
            httpsPort = server.HttpsPort;
            httpPort = server.HttpPort;
            using var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                ConnectCallback = async (context, token) =>
                {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(IPAddress.Loopback, context.DnsEndPoint.Port, token).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch { socket.Dispose(); throw; }
                },
                SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                        errors == SslPolicyErrors.RemoteCertificateChainErrors && certificate is X509Certificate2 cert &&
                        cert.GetNameInfo(X509NameType.DnsName, false) == DownloadServer.TargetHost
                }
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2) };
            using var response = await client.GetAsync($"https://{DownloadServer.TargetHost}:{httpsPort}/selftest.apk", HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.PartialContent || response.Content.Headers.ContentLength != expectedLength ||
                response.Content.Headers.ContentRange?.From != 0 || response.Content.Headers.ContentRange.To != expectedLength - 1 ||
                response.Content.Headers.ContentRange.Length != expectedLength)
                throw new InvalidDataException("Local HTTPS transfer returned unexpected status or length metadata.");
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var body = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            var buffer = new byte[65536];
            using var transfer = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            int count;
            while ((count = await body.ReadAsync(buffer, transfer.Token).ConfigureAwait(false)) != 0)
            {
                digest.AppendData(buffer, 0, count);
                received += count;
            }
            var actualHash = digest.GetHashAndReset();
            sha256 = Convert.ToHexString(actualHash);
            if (received != expectedLength || !CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
                throw new InvalidDataException("Local HTTPS transfer bytes or SHA-256 did not match the input payload.");
            await server.StopAsync().ConfigureAwait(false);
        }
        catch (Exception error) { failure = error; }

        using var receipt = new MemoryStream();
        using (var writer = new Utf8JsonWriter(receipt, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("test", "local-http-tls-apk-download");
            writer.WriteBoolean("success", failure is null);
            writer.WriteBoolean("hardwareTested", false);
            writer.WriteString("targetHost", DownloadServer.TargetHost);
            writer.WriteNumber("httpsPort", httpsPort);
            writer.WriteNumber("httpPort", httpPort);
            writer.WriteNumber("receivedBytes", received);
            writer.WriteString("sha256", sha256);
            writer.WriteString("error", failure?.Message);
            writer.WriteEndObject();
        }
        await File.WriteAllBytesAsync(reportPath, receipt.ToArray()).ConfigureAwait(false);
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
