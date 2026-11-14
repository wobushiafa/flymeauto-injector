using System.Net;

namespace FlymeNative.Core;

internal static class DownloadProxy
{
    private static readonly string[] HopHeaders =
        ["Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Connection"];

    public static async Task SendAsync(HttpClient client, Stream stream, DownloadRequest request, bool secure, CancellationToken token, Action<string> log)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        var transferToken = deadline.Token;
        using var message = new HttpRequestMessage(new HttpMethod(request.Method),
            new Uri($"{(secure ? "https" : "http")}://{DownloadServer.TargetHost}{request.PathAndQuery}"));
        if (request.ContentLength > 0)
        {
            message.Content = new StreamContent(new DownloadBodyStream(stream, request.ContentLength));
            message.Content.Headers.ContentLength = request.ContentLength;
        }
        var excluded = Excluded(request.Headers.GetValueOrDefault("Connection"));
        excluded.Add("Host");
        excluded.Add("Content-Length");
        foreach (var (name, value) in request.Headers)
        {
            if (excluded.Contains(name)) continue;
            if (!message.Headers.TryAddWithoutValidation(name, value))
            {
                message.Content ??= new ByteArrayContent([]);
                message.Content.Headers.TryAddWithoutValidation(name, value);
            }
        }
        HttpResponseMessage response;
        try { response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, transferToken).ConfigureAwait(false); }
        catch (Exception error) when (error is HttpRequestException or OperationCanceledException or IOException)
        {
            if (token.IsCancellationRequested) throw;
            log($"Upstream request failed: {error.GetType().Name}: {error.Message}");
            await DownloadResponse.EmptyAsync(stream, 502, token).ConfigureAwait(false);
            return;
        }
        using (response)
        {
            var responseExcluded = Excluded(string.Join(",", response.Headers.Connection));
            var headers = response.Headers.Concat(response.Content.Headers)
                .Where(header => !responseExcluded.Contains(header.Key))
                .SelectMany(header => header.Value.Select(value => new KeyValuePair<string, string>(header.Key, value)));
            await DownloadResponse.WriteHeadersAsync(stream, (int)response.StatusCode, headers, transferToken).ConfigureAwait(false);
            long sent = 0;
            try
            {
                if (request.Method != "HEAD" && response.StatusCode is not (HttpStatusCode.NoContent or HttpStatusCode.NotModified))
                {
                    using var body = await response.Content.ReadAsStreamAsync(transferToken).ConfigureAwait(false);
                    var buffer = new byte[65536];
                    int count;
                    while ((count = await body.ReadAsync(buffer, transferToken).ConfigureAwait(false)) != 0)
                    {
                        await stream.WriteAsync(buffer.AsMemory(0, count), transferToken).ConfigureAwait(false);
                        sent += count;
                    }
                }
            }
            finally { log($"Upstream {request.Method}: {(int)response.StatusCode}, {sent} body bytes sent to socket."); }
        }
    }

    private static HashSet<string> Excluded(string? connection)
    {
        var result = new HashSet<string>(HopHeaders, StringComparer.OrdinalIgnoreCase);
        if (connection is not null)
            foreach (var name in connection.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)) result.Add(name);
        return result;
    }
}

// Limits HttpClient's request-body reads to the parsed framing; leaves the response socket open.
internal sealed class DownloadBodyStream(Stream inner, long length) : Stream
{
    private readonly long totalLength = length;
    private long remaining = length;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => totalLength;
    public override long Position { get => totalLength - remaining; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (remaining == 0 || buffer.Length == 0) return 0;
        var count = await inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, remaining)], cancellationToken).ConfigureAwait(false);
        if (count == 0) throw new IOException("Incomplete upstream request body.");
        remaining -= count;
        return count;
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
