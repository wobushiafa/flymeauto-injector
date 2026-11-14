using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace FlymeNative.Core;

internal static class DownloadResponse
{
    public static Task EmptyAsync(Stream stream, int status, CancellationToken token) =>
        WriteHeadersAsync(stream, status, [new("Content-Length", "0")], token);

    public static async Task WriteHeadersAsync(Stream stream, int status, IEnumerable<KeyValuePair<string, string>> headers, CancellationToken token)
    {
        var reason = status switch
        {
            206 => "Partial Content", 400 => "Bad Request", 405 => "Method Not Allowed", 416 => "Range Not Satisfiable",
            417 => "Expectation Failed", 421 => "Misdirected Request", 431 => "Request Header Fields Too Large", 502 => "Bad Gateway", _ => "Response"
        };
        var builder = new StringBuilder($"HTTP/1.1 {status} {reason}\r\nConnection: close\r\n");
        foreach (var (name, value) in headers)
        {
            if (name.Contains('\r') || name.Contains('\n') || value.Contains('\r') || value.Contains('\n'))
                throw new InvalidDataException("Invalid upstream response header.");
            builder.Append(name).Append(": ").Append(value).Append("\r\n");
        }
        builder.Append("\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(builder.ToString()), token).ConfigureAwait(false);
    }
}

internal sealed class DownloadPayload
{
    private readonly byte[] bytes;
    private readonly string md5;
    private readonly string etag;

    public DownloadPayload(byte[] snapshot)
    {
        bytes = snapshot;
        var digest = MD5.HashData(bytes);
        md5 = Convert.ToBase64String(digest);
        etag = $"\"{Convert.ToHexString(digest)}\"";
    }

    public async Task SendAsync(Stream stream, DownloadRequest request, CancellationToken token, Action<string> log)
    {
        if (request.Method is not ("GET" or "HEAD"))
        {
            await DownloadResponse.WriteHeadersAsync(stream, 405, [new("Allow", "GET, HEAD"), new("Content-Length", "0")], token).ConfigureAwait(false);
            return;
        }
        var range = ParseRange(request.Headers.GetValueOrDefault("Range"));
        if (range is null)
        {
            log($"[HTTP响应] status=416; Range={request.Headers.GetValueOrDefault("Range")}; total={bytes.Length}");
            await DownloadResponse.WriteHeadersAsync(stream, 416, [new("Content-Range", $"bytes */{bytes.Length}"), new("Content-Length", "0")], token).ConfigureAwait(false);
            return;
        }
        var (start, end) = range.Value;
        var length = end - start + 1;
        log($"[HTTP响应] status=206; Content-Range=bytes {start}-{end}/{bytes.Length}; Content-Length={length}; method={request.Method}");
        await DownloadResponse.WriteHeadersAsync(stream, 206,
        [
            new("Content-Type", "application/vnd.android.package-archive"),
            new("Content-Length", length.ToString(CultureInfo.InvariantCulture)),
            new("Content-Range", $"bytes {start}-{end}/{bytes.Length}"),
            new("Accept-Ranges", "bytes"), new("ETag", etag), new("Content-MD5", md5), new("Server", "Tengine")
        ], token).ConfigureAwait(false);
        long sent = 0;
        long lastReport = 0;
        try
        {
            if (request.Method == "GET")
            {
                while (sent < length)
                {
                    var count = (int)Math.Min(65536, length - sent);
                    await stream.WriteAsync(bytes.AsMemory(start + (int)sent, count), token).ConfigureAwait(false);
                    sent += count;
                    if (sent - lastReport >= 1048576 || sent == length)
                    {
                        lastReport = sent;
                        log($"[APK发送进度] {sent}/{length} 字节，{sent * 100.0 / length:F1}%");
                    }
                }
            }
            await stream.FlushAsync(token).ConfigureAwait(false);
            log($"[APK发送完成] method={request.Method}; sent={sent}; selected={length}; total={bytes.Length}; 已写入套接字，不代表已安装");
        }
        finally { log($"Local APK {request.Method}: {sent} body bytes sent to socket; selected {length} of {bytes.Length} bytes."); }
    }

    private (int Start, int End)? ParseRange(string? header)
    {
        if (header is null) return (0, bytes.Length - 1);
        if (!header.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase) || header.Contains(',')) return null;
        var range = header.AsSpan(6);
        var dash = range.IndexOf('-');
        if (dash < 0) return null;
        var left = range[..dash];
        var right = range[(dash + 1)..];
        if (left.IsEmpty)
        {
            if (!long.TryParse(right, NumberStyles.None, CultureInfo.InvariantCulture, out var suffix) || suffix <= 0) return null;
            return ((int)Math.Max(0, bytes.Length - suffix), bytes.Length - 1);
        }
        if (!long.TryParse(left, NumberStyles.None, CultureInfo.InvariantCulture, out var start) || start >= bytes.Length) return null;
        long end = bytes.Length - 1;
        if (!right.IsEmpty && !long.TryParse(right, NumberStyles.None, CultureInfo.InvariantCulture, out end)) return null;
        if (end < start) return null;
        return ((int)start, (int)Math.Min(end, bytes.Length - 1));
    }
}
