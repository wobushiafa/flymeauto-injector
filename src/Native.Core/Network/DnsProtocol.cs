using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace FlymeNative.Core;

public static class DnsProtocol
{
    private static ReadOnlySpan<byte> Target => "\u000ccarapp-a-res\u0009flymeauto\u0003com\0"u8;

    public static byte[]? Reply(ReadOnlySpan<byte> query, IPAddress gateway)
    {
        if (gateway.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("DNS gateway must be IPv4.", nameof(gateway));
        if (query.Length is < 17 or > 4096 || Read16(query, 4) != 1 ||
            Read16(query, 6) != 0 || Read16(query, 8) != 0 ||
            (Read16(query, 2) & ~0x0110) != 0 || Read16(query, 10) > 1)
            return null;

        Span<byte> name = stackalloc byte[255];
        Span<byte> wireName = stackalloc byte[255];
        int cursor = 12, nameSize = 0, wireSize = 0, end = -1, jumps = 0;
        while (true)
        {
            if ((uint)cursor >= (uint)query.Length) return null;
            byte length = query[cursor++];
            if ((length & 0xc0) == 0xc0)
            {
                if (cursor >= query.Length || ++jumps > 16) return null;
                int pointer = ((length & 0x3f) << 8) | query[cursor++];
                if (end < 0) end = cursor;
                cursor = pointer;
                continue;
            }
            if (length > 63 || wireSize + length + 1 > 255) return null;
            wireName[wireSize++] = length;
            name[nameSize++] = length;
            if (length == 0) break;
            if (cursor + length > query.Length) return null;
            for (int i = 0; i < length; i++)
            {
                byte c = query[cursor + i];
                wireName[wireSize++] = c;
                name[nameSize++] = c is >= (byte)'A' and <= (byte)'Z' ? (byte)(c + 32) : c;
            }
            cursor += length;
        }
        int questionEnd = end < 0 ? cursor : end;
        if (!name[..nameSize].SequenceEqual(Target) || questionEnd + 4 > query.Length) return null;
        ushort type = Read16(query, questionEnd);
        if (Read16(query, questionEnd + 2) != 1 || type is not (1 or 28 or 64 or 65)) return null;
        int tail = questionEnd + 4;
        if (Read16(query, 10) == 1)
        {
            // Accept one bounded EDNS OPT, never copy client cookies/options into the answer.
            if (tail + 11 > query.Length || query[tail] != 0 || Read16(query, tail + 1) != 41 ||
                query[tail + 5] != 0 || query[tail + 6] != 0) return null;
            int optEnd = tail + 11 + Read16(query, tail + 9);
            if (optEnd != query.Length) return null;
            int option = tail + 11;
            while (option < optEnd)
            {
                if (option + 4 > optEnd) return null;
                option += 4 + Read16(query, option + 2);
                if (option > optEnd) return null;
            }
            tail = optEnd;
        }
        if (tail != query.Length) return null;

        int baseLength = 12 + wireSize + 4;
        byte[] reply = new byte[baseLength + (type == 1 ? 16 : 0)];
        query[..2].CopyTo(reply);
        Write16(reply, 2, (ushort)(0x8080 | (Read16(query, 2) & 0x0110)));
        Write16(reply, 4, 1);
        Write16(reply, 6, type == 1 ? (ushort)1 : (ushort)0);
        wireName[..wireSize].CopyTo(reply.AsSpan(12));
        query.Slice(questionEnd, 4).CopyTo(reply.AsSpan(12 + wireSize));
        if (type == 1)
        {
            Span<byte> answer = reply.AsSpan(baseLength);
            answer[0] = 0xc0; answer[1] = 12;
            Write16(answer, 2, 1); Write16(answer, 4, 1);
            BinaryPrimitives.WriteUInt32BigEndian(answer[6..], 30);
            Write16(answer, 10, 4);
            gateway.TryWriteBytes(answer[12..], out _);
        }
        return reply;
    }

    private static ushort Read16(ReadOnlySpan<byte> bytes, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
    private static void Write16(Span<byte> bytes, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16BigEndian(bytes[offset..], value);
}
