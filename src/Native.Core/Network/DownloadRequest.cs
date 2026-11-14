using System.Globalization;
using System.Text;

namespace FlymeNative.Core;

internal sealed class DownloadProtocolException(int status) : Exception
{
    public int Status { get; } = status;
}

internal sealed record DownloadRequest(string Method, string PathAndQuery, Uri Uri, IReadOnlyDictionary<string, string> Headers, long ContentLength)
{
    public bool IsTargetHost
    {
        get
        {
            if (!Headers.TryGetValue("Host", out var host)) return false;
            var parts = host.Split(':');
            return parts[0].Equals(DownloadServer.TargetHost, StringComparison.OrdinalIgnoreCase) &&
                (parts.Length == 1 || (parts.Length == 2 && ushort.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port > 0));
        }
    }

    public bool IsApk => Uri.AbsolutePath.EndsWith(".apk", StringComparison.OrdinalIgnoreCase);

    public static async Task<DownloadRequest> ReadAsync(Stream stream, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var buffer = new byte[32768];
        var length = 0;
        while (true)
        {
            if (length == buffer.Length) throw new DownloadProtocolException(431);
            var count = await stream.ReadAsync(buffer.AsMemory(length, 1), deadline.Token).ConfigureAwait(false);
            if (count == 0) throw new IOException("Client closed before request headers completed.");
            var value = buffer[length++];
            if (value > 126 || (value < 32 && value is not (9 or 10 or 13))) throw new DownloadProtocolException(400);
            if (length >= 4 && buffer.AsSpan(length - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
        }
        var lines = Encoding.ASCII.GetString(buffer, 0, length - 4).Split("\r\n", StringSplitOptions.None);
        var first = lines[0].Split(' ');
        if (first.Length != 3 || first[2] is not ("HTTP/1.1" or "HTTP/1.0") || !IsToken(first[0]) ||
            !first[1].StartsWith('/') || first[1].StartsWith("//", StringComparison.Ordinal) || first[1].Contains('#') || first[1].Contains('\\') ||
            !System.Uri.TryCreate("http://" + DownloadServer.TargetHost + first[1], UriKind.Absolute, out var uri))
            throw new DownloadProtocolException(400);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon < 1 || !IsToken(line[..colon])) throw new DownloadProtocolException(400);
            var name = line[..colon];
            var value = line[(colon + 1)..].Trim(' ', '\t');
            if (value.Contains('\r') || value.Contains('\n')) throw new DownloadProtocolException(400);
            if (!headers.TryAdd(name, value))
            {
                if (name.Equals("Host", StringComparison.OrdinalIgnoreCase) || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                    throw new DownloadProtocolException(400);
                headers[name] += ", " + value;
            }
        }
        if (!headers.ContainsKey("Host")) throw new DownloadProtocolException(400);
        // One request per connection. Unsupported framing is explicitly refused, never guessed.
        if (headers.ContainsKey("Transfer-Encoding")) throw new DownloadProtocolException(400);
        if (headers.ContainsKey("Expect")) throw new DownloadProtocolException(417);
        long contentLength = 0;
        if (headers.TryGetValue("Content-Length", out var text) &&
            (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out contentLength) || contentLength > 64 * 1024 * 1024))
            throw new DownloadProtocolException(400);
        return new DownloadRequest(first[0], first[1], uri, headers, contentLength);
    }

    private static bool IsToken(string text) => text.Length > 0 && text.All(c =>
        char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c));
}
