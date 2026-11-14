using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FlymeNative.Core;

internal static class ApkV2Signature
{
    public static byte[] Create(FileStream archive, long centralOffset, X509Certificate2 certificate)
    {
        var digest = Digest(archive, centralOffset);
        using var rsa = certificate.GetRSAPrivateKey() ?? throw new CryptographicException("Missing RSA signing key.");
        var signedData = Join(Prefix(Join(Prefix(Join(Algorithm(), Prefix(digest))))),
            Prefix(Prefix(certificate.RawData)), Prefix([]));
        var signature = rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signer = Join(Prefix(signedData), Prefix(Prefix(Join(Algorithm(), Prefix(signature)))), Prefix(rsa.ExportSubjectPublicKeyInfo()));
        return Prefix(Prefix(signer));
    }

    public static void WriteBlock(Stream output, byte[] signature, long padding)
    {
        using var writer = new BinaryWriter(output, Encoding.UTF8, true);
        var size = checked((ulong)(48 + signature.Length + padding));
        writer.Write(size);
        writer.Write((ulong)(signature.Length + 4)); writer.Write(0x7109871au); writer.Write(signature);
        writer.Write(checked((ulong)(padding + 4))); writer.Write(0x42726577u);
        ZipOutput.Zeros(output, padding);
        writer.Write(size); writer.Write("APK Sig Block 42"u8);
    }

    // Each of the three signed regions starts a fresh 1 MiB chunk sequence (AOSP v2).
    private static byte[] Digest(FileStream archive, long centralOffset)
    {
        const int chunkSize = 1024 * 1024;
        var sections = new[] { (Start: 0L, Length: centralOffset),
            (Start: centralOffset, Length: archive.Length - centralOffset - 22), (Start: archive.Length - 22, Length: 22L) };
        var count = checked((uint)sections.Sum(section => (section.Length + chunkSize - 1) / chunkSize));
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> header = stackalloc byte[5];
        header[0] = 0x5a;
        BinaryPrimitives.WriteUInt32LittleEndian(header[1..], count);
        aggregate.AppendData(header);
        var buffer = new byte[chunkSize];
        foreach (var section in sections)
        {
            archive.Position = section.Start;
            var remaining = section.Length;
            while (remaining > 0)
            {
                var length = (int)Math.Min(remaining, chunkSize);
                archive.ReadExactly(buffer.AsSpan(0, length));
                header[0] = 0xa5;
                BinaryPrimitives.WriteUInt32LittleEndian(header[1..], checked((uint)length));
                using var chunk = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                chunk.AppendData(header); chunk.AppendData(buffer.AsSpan(0, length));
                aggregate.AppendData(chunk.GetHashAndReset());
                remaining -= length;
            }
        }
        return aggregate.GetHashAndReset();
    }

    private static byte[] Algorithm() => [3, 1, 0, 0]; // 0x0103: RSA PKCS#1 v1.5, SHA-256.

    private static byte[] Prefix(byte[] bytes)
    {
        var result = new byte[bytes.Length + 4];
        BinaryPrimitives.WriteInt32LittleEndian(result, bytes.Length);
        bytes.CopyTo(result, 4);
        return result;
    }

    private static byte[] Join(params byte[][] values)
    {
        using var stream = new MemoryStream();
        foreach (var value in values) stream.Write(value);
        return stream.ToArray();
    }
}
