using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;

namespace FlymeNative.Core;

internal sealed class GatewayDnsExchange(IPAddress gateway)
{
    private readonly ConcurrentDictionary<(uint Client, ushort Port, ushort Id), PendingDns> pending = new();
    private sealed record PendingDns(byte[] Response, long Created);

    internal bool Remember(ReadOnlySpan<byte> packet)
    {
        if (!TryUdp(packet, out int offset) || !packet.Slice(16, 4).SequenceEqual(gateway.GetAddressBytes()) ||
            BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..]) != 53) return false;
        byte[]? answer = DnsProtocol.Reply(packet[(offset + 8)..], gateway);
        if (answer is null) return false;
        if (pending.Count >= 512)
        {
            long oldest = Environment.TickCount64 - 15000;
            foreach (var item in pending)
                if (item.Value.Created < oldest) pending.TryRemove(item.Key, out _);
            if (pending.Count >= 512) return false;
        }
        var key = (BinaryPrimitives.ReadUInt32BigEndian(packet[12..]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]), BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 8)..]));
        pending[key] = new PendingDns(answer, Environment.TickCount64);
        return true;
    }

    internal byte[]? Rewrite(ReadOnlySpan<byte> packet, bool preserveOriginal = false)
    {
        if (!TryUdp(packet, out int offset) || !packet.Slice(12, 4).SequenceEqual(gateway.GetAddressBytes()) ||
            BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]) != 53 || packet.Length < offset + 20 ||
            (packet[offset + 10] & 0x80) == 0) return null;
        var key = (BinaryPrimitives.ReadUInt32BigEndian(packet[16..]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..]), BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 8)..]));
        if (!pending.TryGetValue(key, out var query)) return null;
        if (Environment.TickCount64 - query.Created > 15000) { pending.TryRemove(key, out _); return null; }
        var originalDns = packet[(offset + 8)..];
        int questionType = BinaryPrimitives.ReadUInt16BigEndian(query.Response.AsSpan(query.Response.Length - (BinaryPrimitives.ReadUInt16BigEndian(query.Response.AsSpan(6)) == 1 ? 16 : 0) - 4));
        if (!MatchesQuestion(originalDns, query.Response)) return null;
        byte[]? answer = questionType == 1 ? DnsAnswerPatch.ReplaceAddresses(originalDns, gateway) : query.Response;
        if (answer is null) return null;
        if (!pending.TryRemove(KeyValuePair.Create(key, query))) return null;
        if (preserveOriginal) return packet.ToArray();
        byte[] result = new byte[offset + 8 + answer.Length];
        packet[..(offset + 8)].CopyTo(result);
        answer.CopyTo(result.AsSpan(offset + 8));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), checked((ushort)result.Length));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 4), checked((ushort)(result.Length - offset)));
        result[10] = result[11] = result[offset + 6] = result[offset + 7] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), Checksum(result.AsSpan(0, offset), 0));
        uint pseudo = Sum(result.AsSpan(12, 8)) + 17u + (uint)(result.Length - offset);
        ushort udp = Checksum(result.AsSpan(offset), pseudo);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 6), udp == 0 ? ushort.MaxValue : udp);
        return result;
    }

    private static bool MatchesQuestion(ReadOnlySpan<byte> response, ReadOnlySpan<byte> expected)
    {
        if (response.Length < 17 || BinaryPrimitives.ReadUInt16BigEndian(response[4..]) != 1) return false;
        Span<byte> name = stackalloc byte[255];
        int cursor = 12, length = 0, end = -1, jumps = 0;
        while (cursor < response.Length)
        {
            int count = response[cursor++];
            if ((count & 0xc0) == 0xc0)
            {
                if (cursor >= response.Length || ++jumps > 16) return false;
                if (end < 0) end = cursor + 1;
                cursor = ((count & 63) << 8) | response[cursor];
                continue;
            }
            if (count > 63 || count > response.Length - cursor || length + count + 1 > name.Length) return false;
            name[length++] = (byte)count;
            for (int index = 0; index < count; index++)
            {
                byte value = response[cursor++];
                name[length++] = value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;
            }
            if (count != 0) continue;
            int tail = end < 0 ? cursor : end;
            if (tail + 4 > response.Length || 12 + length + 4 > expected.Length) return false;
            for (int index = 0; index < length; index++)
            {
                byte value = expected[12 + index];
                byte normalized = value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;
                if (name[index] != normalized) return false;
            }
            return response.Slice(tail, 4).SequenceEqual(expected.Slice(12 + length, 4));
        }
        return false;
    }

    private static bool TryUdp(ReadOnlySpan<byte> packet, out int offset)
    {
        offset = packet.Length > 0 ? (packet[0] & 15) * 4 : 0;
        return packet.Length >= 40 && packet[0] >> 4 == 4 && packet[9] == 17 && offset >= 20 && offset + 20 <= packet.Length &&
            BinaryPrimitives.ReadUInt16BigEndian(packet[2..]) == packet.Length &&
            (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3fff) == 0 &&
            BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 4)..]) == packet.Length - offset;
    }

    private static uint Sum(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0;
        for (int i = 0; i < bytes.Length; i++) sum += (uint)bytes[i] << (i % 2 == 0 ? 8 : 0);
        return sum;
    }

    private static ushort Checksum(ReadOnlySpan<byte> bytes, uint initial)
    {
        uint sum = initial + Sum(bytes);
        while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        return (ushort)~sum;
    }
}
