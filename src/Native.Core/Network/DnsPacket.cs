using System.Buffers.Binary;
using System.Net;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Native.DnsTests")]
[assembly: InternalsVisibleTo("Native.RedirectTests")]

namespace FlymeNative.Core;

internal static class DnsPacket
{
    internal static byte[]? Reply(ReadOnlySpan<byte> packet, IPAddress gateway)
    {
        if (packet.Length < 28 || packet[0] >> 4 != 4 || packet[9] != 17) return null;
        int header = (packet[0] & 15) * 4;
        if (header < 20 || header + 8 > packet.Length ||
            BinaryPrimitives.ReadUInt16BigEndian(packet[2..]) != packet.Length ||
            (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3fff) != 0) return null;
        ReadOnlySpan<byte> udp = packet[header..];
        if (BinaryPrimitives.ReadUInt16BigEndian(udp[2..]) != 53 ||
            BinaryPrimitives.ReadUInt16BigEndian(udp[4..]) != udp.Length) return null;
        byte[]? dns = DnsProtocol.Reply(udp[8..], gateway);
        if (dns is null) return null;
        // Fresh IPv4 header avoids replaying request-only IP options and fragmentation state.
        byte[] reply = new byte[28 + dns.Length];
        reply[0] = 0x45; reply[8] = 64; reply[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(2), (ushort)reply.Length);
        packet.Slice(16, 4).CopyTo(reply.AsSpan(12));
        packet.Slice(12, 4).CopyTo(reply.AsSpan(16));
        udp.Slice(2, 2).CopyTo(reply.AsSpan(20));
        udp[..2].CopyTo(reply.AsSpan(22));
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(24), (ushort)(dns.Length + 8));
        dns.CopyTo(reply.AsSpan(28));
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(10), Checksum(reply.AsSpan(0, 20), 0));
        uint pseudo = Sum(reply.AsSpan(12, 8), 0) + 17u + (uint)(reply.Length - 20);
        ushort checksum = Checksum(reply.AsSpan(20), pseudo);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(26), checksum == 0 ? ushort.MaxValue : checksum);
        return reply;
    }

    private static uint Sum(ReadOnlySpan<byte> bytes, uint sum)
    {
        int i = 0;
        for (; i + 1 < bytes.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(bytes[i..]);
        if (i < bytes.Length) sum += (uint)bytes[i] << 8;
        return sum;
    }

    private static ushort Checksum(ReadOnlySpan<byte> bytes, uint initial)
    {
        uint sum = Sum(bytes, initial);
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return (ushort)~sum;
    }
}
