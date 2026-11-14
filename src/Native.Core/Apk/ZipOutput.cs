using System.Text;

namespace FlymeNative.Core;

internal sealed class ZipOutput(Stream output)
{
    private readonly List<byte[]> directory = [];
    private static readonly uint[] CrcTable = Enumerable.Range(0, 256).Select(value =>
    {
        var crc = (uint)value;
        for (var bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0);
        return crc;
    }).ToArray();

    public void Copy(FileStream source, ZipPayload entry)
    {
        Header(entry);
        source.Position = entry.DataOffset;
        CopyBytes(source, output, entry.CompressedSize);
    }

    public void Add(string name, byte[] bytes)
    {
        Header(new ZipPayload(name, Encoding.UTF8.GetBytes(name), 0, ~UpdateCrc(uint.MaxValue, bytes),
            checked((uint)bytes.Length), checked((uint)bytes.Length), 0, []));
        output.Write(bytes);
    }

    private void Header(ZipPayload entry)
    {
        var offset = checked((uint)output.Position);
        var alignment = entry.Method == 0 ? (entry.Name.StartsWith("lib/", StringComparison.Ordinal) && entry.Name.EndsWith(".so", StringComparison.Ordinal) ? 16384 : 4) : 1;
        var padding = (int)((alignment - (output.Position + 30 + entry.NameBytes.Length) % alignment) % alignment);
        while (padding is > 0 and < 6) padding += alignment;
        using var writer = new BinaryWriter(output, Encoding.UTF8, true);
        writer.Write(0x04034b50u);
        writer.Write((ushort)20); writer.Write((ushort)0x800); writer.Write(entry.Method);
        writer.Write((ushort)0); writer.Write((ushort)33);
        writer.Write(entry.Crc); writer.Write(entry.CompressedSize); writer.Write(entry.Size);
        writer.Write(checked((ushort)entry.NameBytes.Length)); writer.Write(checked((ushort)padding));
        writer.Write(entry.NameBytes);
        if (padding > 0)
        {
            writer.Write((ushort)0xd935); writer.Write(checked((ushort)(padding - 4)));
            writer.Write(checked((ushort)alignment));
            Zeros(output, padding - 6);
        }
        using var central = new MemoryStream();
        using var cd = new BinaryWriter(central, Encoding.UTF8, true);
        cd.Write(0x02014b50u); cd.Write((ushort)20); cd.Write((ushort)20);
        cd.Write((ushort)0x800); cd.Write(entry.Method); cd.Write((ushort)0); cd.Write((ushort)33);
        cd.Write(entry.Crc); cd.Write(entry.CompressedSize); cd.Write(entry.Size);
        cd.Write(checked((ushort)entry.NameBytes.Length)); cd.Write((ushort)0); cd.Write((ushort)0);
        cd.Write((ushort)0); cd.Write((ushort)0); cd.Write(0u); cd.Write(offset); cd.Write(entry.NameBytes);
        directory.Add(central.ToArray());
    }

    public long Finish()
    {
        var start = output.Position;
        foreach (var entry in directory) output.Write(entry);
        using var writer = new BinaryWriter(output, Encoding.UTF8, true);
        writer.Write(0x06054b50u); writer.Write((ushort)0); writer.Write((ushort)0);
        writer.Write(checked((ushort)directory.Count)); writer.Write(checked((ushort)directory.Count));
        writer.Write(checked((uint)(output.Position - start - 12))); writer.Write(checked((uint)start)); writer.Write((ushort)0);
        return start;
    }

    internal static uint UpdateCrc(uint crc, ReadOnlySpan<byte> bytes)
    {
        foreach (var value in bytes) crc = CrcTable[(crc ^ value) & 255] ^ (crc >> 8);
        return crc;
    }

    internal static void CopyBytes(Stream source, Stream destination, long length)
    {
        var buffer = new byte[65536];
        while (length > 0)
        {
            var count = (int)Math.Min(length, buffer.Length);
            source.ReadExactly(buffer.AsSpan(0, count));
            destination.Write(buffer.AsSpan(0, count));
            length -= count;
        }
    }

    internal static void Zeros(Stream stream, long count)
    {
        var buffer = new byte[65536];
        while (count > 0)
        {
            var length = (int)Math.Min(count, buffer.Length);
            stream.Write(buffer.AsSpan(0, length));
            count -= length;
        }
    }
}
