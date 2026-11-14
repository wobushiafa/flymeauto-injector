using System.Buffers.Binary;
using System.Text;

namespace FlymeNative.Core;

internal static class TlsHelloObservation
{
    internal static string? ServerName(ReadOnlySpan<byte> record)
    {
        if (record.Length < 9 || record[0] != 22 || record[1] != 3 || record[5] != 1) return null;
        int recordLength = BinaryPrimitives.ReadUInt16BigEndian(record[3..]);
        if (recordLength + 5 > record.Length) return null;
        int helloLength = (record[6] << 16) | (record[7] << 8) | record[8];
        if (helloLength < 38 || helloLength + 4 > recordLength) return null;
        var hello = record.Slice(9, helloLength);
        int cursor = 34;
        if (cursor >= hello.Length) return null;
        cursor += 1 + hello[cursor];
        if (cursor + 2 > hello.Length) return null;
        cursor += 2 + BinaryPrimitives.ReadUInt16BigEndian(hello[cursor..]);
        if (cursor >= hello.Length) return null;
        cursor += 1 + hello[cursor];
        if (cursor + 2 > hello.Length) return null;
        int end = cursor + 2 + BinaryPrimitives.ReadUInt16BigEndian(hello[cursor..]);
        cursor += 2;
        if (end > hello.Length) return null;
        while (cursor + 4 <= end)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(hello[cursor..]);
            int length = BinaryPrimitives.ReadUInt16BigEndian(hello[(cursor + 2)..]);
            cursor += 4;
            if (length > end - cursor) return null;
            if (type == 0)
            {
                if (length < 5) return null;
                var names = hello.Slice(cursor, length);
                if (BinaryPrimitives.ReadUInt16BigEndian(names) != length - 2) return null;
                int pos = 2;
                while (pos + 3 <= names.Length)
                {
                    byte nameType = names[pos];
                    int count = BinaryPrimitives.ReadUInt16BigEndian(names[(pos + 1)..]);
                    pos += 3;
                    if (count > names.Length - pos) return null;
                    if (nameType == 0)
                    {
                        if (count is < 1 or > 253) return null;
                        var bytes = names.Slice(pos, count);
                        foreach (byte value in bytes)
                            if (!(value is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'.' or (byte)'-')) return null;
                        return Encoding.ASCII.GetString(bytes).ToLowerInvariant();
                    }
                    pos += count;
                }
                return null;
            }
            cursor += length;
        }
        return null;
    }
}
