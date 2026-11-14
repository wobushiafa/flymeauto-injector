using System.Buffers.Binary;
using System.Net;

namespace FlymeNative.Core;

internal static class DnsAnswerPatch
{
    internal static byte[]? ReplaceAddresses(ReadOnlySpan<byte> response, IPAddress address)
    {
        if (response.Length < 17 || response.Length > 65507 || address.GetAddressBytes().Length != 4 ||
            (response[2] & 0x80) == 0 || (response[3] & 15) != 0 || Read16(response, 4) != 1) return null;
        int cursor = SkipName(response, 12);
        if (cursor < 0 || cursor + 4 > response.Length || Read16(response, cursor) != 1 || Read16(response, cursor + 2) != 1) return null;
        cursor += 4;
        int answerCount = Read16(response, 6);
        int recordCount = answerCount + Read16(response, 8) + Read16(response, 10);
        if (answerCount is 0 or > 256 || recordCount > 512) return null;
        List<int> locations = [];
        for (int record = 0; record < recordCount; record++)
        {
            cursor = SkipName(response, cursor);
            if (cursor < 0 || cursor + 10 > response.Length) return null;
            int type = Read16(response, cursor), family = Read16(response, cursor + 2), length = Read16(response, cursor + 8);
            cursor += 10;
            if (length > response.Length - cursor) return null;
            if (record < answerCount && type == 1 && family == 1)
            {
                if (length != 4) return null;
                locations.Add(cursor);
            }
            cursor += length;
        }
        if (cursor != response.Length || locations.Count == 0) return null;
        byte[] result = response.ToArray();
        byte[] ipv4 = address.GetAddressBytes();
        foreach (int location in locations) ipv4.CopyTo(result.AsSpan(location, 4));
        return result;
    }

    private static int SkipName(ReadOnlySpan<byte> message, int position)
    {
        int count = 0;
        while (position < message.Length)
        {
            int length = message[position++];
            if (length == 0) return position;
            if ((length & 0xc0) == 0xc0)
            {
                if (position >= message.Length) return -1;
                int destination = ((length & 63) << 8) | message[position];
                return destination < position - 1 && destination >= 12 ? position + 1 : -1;
            }
            count += length + 1;
            if (length > 63 || length > message.Length - position || count > 254) return -1;
            position += length;
        }
        return -1;
    }

    private static ushort Read16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
}
