using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace FlymeNative.Core;

internal sealed record ZipPayload(string Name, byte[] NameBytes, ushort Method, uint Crc, uint CompressedSize,
    uint Size, long DataOffset, byte[] Digest);

internal static class ZipSource
{
    public static IReadOnlyList<ZipPayload> Read(FileStream stream)
    {
        var tail = new byte[(int)Math.Min(stream.Length, 65557)];
        stream.Position = stream.Length - tail.Length;
        stream.ReadExactly(tail);
        var end = -1;
        for (var i = tail.Length - 22; i >= 0; i--)
            if (BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(i)) == 0x06054b50 &&
                i + 22 + BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(i + 20)) == tail.Length) { end = i; break; }
        if (end < 0) throw new InvalidDataException("ZIP end record is missing.");
        var eocd = tail.AsSpan(end);
        var count = BinaryPrimitives.ReadUInt16LittleEndian(eocd[10..]);
        var cdSize = BinaryPrimitives.ReadUInt32LittleEndian(eocd[12..]);
        var cdOffset = BinaryPrimitives.ReadUInt32LittleEndian(eocd[16..]);
        if (count == ushort.MaxValue || cdOffset == uint.MaxValue || cdSize == uint.MaxValue ||
            BinaryPrimitives.ReadUInt32LittleEndian(eocd[4..]) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(eocd[8..]) != count ||
            (long)cdOffset + cdSize != stream.Length - tail.Length + end)
            throw new InvalidDataException("ZIP64, split archives, or inconsistent directories are unsupported.");
        var entries = new List<ZipPayload>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        using var reader = new BinaryReader(stream, Encoding.UTF8, true);
        stream.Position = cdOffset;
        for (var i = 0; i < count; i++)
        {
            var header = reader.ReadBytes(46);
            if (header.Length != 46 || BinaryPrimitives.ReadUInt32LittleEndian(header) != 0x02014b50)
                throw new InvalidDataException("Invalid ZIP central directory.");
            var flags = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(8));
            var method = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(10));
            var compressed = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(20));
            var size = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(24));
            var nameBytes = reader.ReadBytes(BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(28)));
            var name = new UTF8Encoding(false, true).GetString(nameBytes);
            if ((flags & ~0x080e) != 0 || method is not (0 or 8) || name.Length == 0 || name.Contains('\0') ||
                name.Contains('\r') || name.Contains('\n') || !names.Add(name) ||
                size == uint.MaxValue || compressed == uint.MaxValue || (method == 0 && compressed != size) ||
                BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(34)) != 0)
                throw new InvalidDataException("Unsupported or duplicate ZIP entry: " + name);
            var next = stream.Position + BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(30)) + BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(32));
            var local = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(42));
            stream.Position = local;
            var localHeader = reader.ReadBytes(30);
            if (localHeader.Length != 30 || BinaryPrimitives.ReadUInt32LittleEndian(localHeader) != 0x04034b50 ||
                BinaryPrimitives.ReadUInt16LittleEndian(localHeader.AsSpan(8)) != method)
                throw new InvalidDataException("Invalid ZIP local header.");
            var localName = reader.ReadBytes(BinaryPrimitives.ReadUInt16LittleEndian(localHeader.AsSpan(26)));
            var dataOffset = stream.Position + BinaryPrimitives.ReadUInt16LittleEndian(localHeader.AsSpan(28));
            if (!localName.AsSpan().SequenceEqual(nameBytes) || dataOffset + compressed > cdOffset)
                throw new InvalidDataException("Invalid ZIP payload range.");
            if (!IsSignature(name))
                entries.Add(new ZipPayload(name, nameBytes, method, BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(16)),
                    compressed, size, dataOffset, []));
            stream.Position = next;
        }
        if (stream.Position != (long)cdOffset + cdSize) throw new InvalidDataException("Invalid ZIP directory length.");
        if (entries.Count > ushort.MaxValue - 4) throw new InvalidDataException("Too many APK entries for ZIP32 signing.");
        if (!entries.Any(e => e.Name == "AndroidManifest.xml")) throw new InvalidDataException("APK has no AndroidManifest.xml.");
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, true, Encoding.UTF8);
        var hashed = new List<ZipPayload>();
        foreach (var entry in entries)
        {
            using var content = (archive.GetEntry(entry.Name) ?? throw new InvalidDataException("ZIP entry missing.")).Open();
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65536];
            long length = 0;
            uint crc = uint.MaxValue;
            if (entry.Name == "AndroidManifest.xml")
            {
                if (entry.Size < 8) throw new InvalidDataException("AndroidManifest.xml is truncated.");
                content.ReadExactly(buffer.AsSpan(0, 8));
                if (BinaryPrimitives.ReadUInt32LittleEndian(buffer) != 0x00080003 ||
                    BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(4)) != entry.Size)
                    throw new InvalidDataException("AndroidManifest.xml is not a binary Android XML document.");
                hash.AppendData(buffer.AsSpan(0, 8));
                crc = ZipOutput.UpdateCrc(crc, buffer.AsSpan(0, 8));
                length = 8;
            }
            int read;
            while ((read = content.Read(buffer)) > 0)
            {
                length += read;
                if (length > entry.Size) throw new InvalidDataException("ZIP expanded length exceeds declaration.");
                hash.AppendData(buffer.AsSpan(0, read));
                crc = ZipOutput.UpdateCrc(crc, buffer.AsSpan(0, read));
            }
            if (length != entry.Size || ~crc != entry.Crc) throw new InvalidDataException("ZIP payload CRC or length mismatch.");
            hashed.Add(entry with { Digest = hash.GetHashAndReset() });
        }
        return hashed;
    }

    private static bool IsSignature(string name)
    {
        if (!name.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase)) return false;
        var leaf = name[9..];
        return !leaf.Contains('/') && (leaf.Equals("MANIFEST.MF", StringComparison.OrdinalIgnoreCase) ||
            leaf.StartsWith("SIG-", StringComparison.OrdinalIgnoreCase) ||
            new[] { ".SF", ".RSA", ".DSA", ".EC" }.Any(extension => leaf.EndsWith(extension, StringComparison.OrdinalIgnoreCase)));
    }
}
