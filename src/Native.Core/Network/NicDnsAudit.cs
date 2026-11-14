using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace FlymeNative.Core;

internal static class NicDnsAudit
{
    internal static void Summarize(string path, Action<string> log)
    {
        using var file = File.OpenRead(path);
        byte[] header = new byte[8];
        List<ushort> links = [];
        int frames = 0, replies = 0;
        while (file.Position < file.Length)
        {
            file.ReadExactly(header);
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(header);
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4));
            if (length is < 12 or > 1048576 || length > file.Length - file.Position + 8 || length % 4 != 0)
                throw new InvalidDataException("pcapng块长度异常。");
            byte[] block = new byte[length - 8];
            file.ReadExactly(block);
            if (BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(block.Length - 4)) != length)
                throw new InvalidDataException("pcapng块尾长度不一致。");
            if (type == 0x0a0d0d0a)
            {
                if (block.Length < 20 || BinaryPrimitives.ReadUInt32LittleEndian(block) != 0x1a2b3c4d)
                    throw new InvalidDataException("仅支持PktMon输出的小端pcapng。");
                links.Clear();
            }
            else if (type == 1)
            {
                if (block.Length < 12) throw new InvalidDataException("pcapng接口块不完整。");
                links.Add(BinaryPrimitives.ReadUInt16LittleEndian(block));
            }
            else if (type == 6 && block.Length >= 24)
            {
                uint index = BinaryPrimitives.ReadUInt32LittleEndian(block);
                uint captured = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(12));
                if (index >= links.Count || captured > block.Length - 24) throw new InvalidDataException("pcapng数据包边界异常。");
                frames++;
                string? message = Describe(block.AsSpan(20, (int)captured), links[(int)index]);
                if (message is not null)
                {
                    replies++;
                    if (replies <= 32) log("[NIC目标DNS] " + message);
                }
            }
        }
        log($"[NIC分析完成] 网卡记录数={frames}; 目标DNS响应记录数={replies}; 捕获可能有重复帧；记录不证明客户端已接受；网卡offload可能使抓包校验和与线上不同");
    }

    internal static string? Describe(ReadOnlySpan<byte> frame, ushort link)
    {
        int start = 0;
        if (link == 1)
        {
            if (frame.Length < 14) return null;
            int protocol = BinaryPrimitives.ReadUInt16BigEndian(frame[12..]);
            if (protocol != 0x0800 && protocol is not (0x8100 or 0x88a8))
            {
                start = WirelessIpv4Offset(frame);
                if (start < 0) return null;
            }
            else
            {
            start = 14;
            for (int tags = 0; tags < 2 && protocol is 0x8100 or 0x88a8; tags++)
            {
                if (start + 4 > frame.Length) return null;
                protocol = BinaryPrimitives.ReadUInt16BigEndian(frame[(start + 2)..]); start += 4;
            }
            if (protocol != 0x0800) return null;
            }
        }
        else if (link == 105)
        {
            start = WirelessIpv4Offset(frame);
            if (start < 0) return null;
        }
        else if (link is not (101 or 228)) return null;
        var ip = frame[start..];
        if (ip.Length < 28 || ip[0] >> 4 != 4 || ip[9] != 17) return null;
        int ihl = (ip[0] & 15) * 4;
        if (ihl < 20 || ihl + 20 > ip.Length || (BinaryPrimitives.ReadUInt16BigEndian(ip[6..]) & 0x3fff) != 0) return null;
        var udp = ip[ihl..];
        if (BinaryPrimitives.ReadUInt16BigEndian(udp) != 53) return null;
        int udpLength = BinaryPrimitives.ReadUInt16BigEndian(udp[4..]);
        if (udpLength < 20) return null;
        var dns = udp[8..];
        if ((dns[2] & 0x80) == 0 || BinaryPrimitives.ReadUInt16BigEndian(dns[4..]) != 1) return null;
        int cursor = 12;
        string? question = ReadName(dns, ref cursor);
        if (question != DownloadServer.TargetHost || cursor + 4 > dns.Length) return null;
        int qtype = BinaryPrimitives.ReadUInt16BigEndian(dns[cursor..]); cursor += 4;
        List<string> addresses = [];
        int records = Math.Min(256, (int)BinaryPrimitives.ReadUInt16BigEndian(dns[6..]));
        for (int record = 0; record < records; record++)
        {
            if (ReadName(dns, ref cursor) is null || cursor + 10 > dns.Length) break;
            int type = BinaryPrimitives.ReadUInt16BigEndian(dns[cursor..]);
            int family = BinaryPrimitives.ReadUInt16BigEndian(dns[(cursor + 2)..]);
            int size = BinaryPrimitives.ReadUInt16BigEndian(dns[(cursor + 8)..]); cursor += 10;
            if (size > dns.Length - cursor) break;
            if (type == 1 && family == 1 && size == 4) addresses.Add(new IPAddress(dns.Slice(cursor, 4)).ToString());
            cursor += size;
        }
        string udpCheck = "捕获不完整";
        if (udpLength <= udp.Length)
        {
            uint pseudo = Sum(ip.Slice(12, 8)) + 17u + (uint)udpLength;
            ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(udp[6..]);
            udpCheck = checksum == 0 ? "字段为0" : Fold(pseudo + Sum(udp[..udpLength])) == 65535 ? "通过" : "不匹配（需核对offload）";
        }
        return $"{new IPAddress(ip.Slice(12, 4))}:53 -> {new IPAddress(ip.Slice(16, 4))}:{BinaryPrimitives.ReadUInt16BigEndian(udp[2..])}; txid={BinaryPrimitives.ReadUInt16BigEndian(dns):X4}; QTYPE={qtype}; A=[{string.Join(',', addresses.Distinct())}]; 数据捕获完整={udpLength <= udp.Length}; IPv4校验和={Fold(Sum(ip[..ihl])) == 65535}; UDP校验和={udpCheck}; flags=0x{BinaryPrimitives.ReadUInt16BigEndian(dns[2..]):X4}";
    }

    private static int WirelessIpv4Offset(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 32) return -1;
        ushort control = BinaryPrimitives.ReadUInt16LittleEndian(frame);
        if ((control & 0x000f) != 8 || (control & 0x4000) != 0) return -1;
        int header = 24 + ((control & 0x0300) == 0x0300 ? 6 : 0);
        bool qos = (control & 0x0080) != 0;
        if (qos) header += 2;
        if (qos && (control & 0x8000) != 0) header += 4;
        if (header + 8 > frame.Length || !frame.Slice(header, 8).SequenceEqual(new byte[] { 0xaa, 0xaa, 3, 0, 0, 0, 8, 0 })) return -1;
        return header + 8;
    }

    private static uint Sum(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0;
        for (int index = 0; index < bytes.Length; index++) sum += (uint)bytes[index] << (index % 2 == 0 ? 8 : 0);
        return sum;
    }

    private static uint Fold(uint value)
    {
        while (value > 65535) value = (value & 65535) + (value >> 16);
        return value;
    }

    private static string? ReadName(ReadOnlySpan<byte> bytes, ref int cursor)
    {
        int pos = cursor, jumps = 0, consumed = -1, total = 0;
        List<string> labels = [];
        while (pos < bytes.Length)
        {
            int count = bytes[pos++];
            if (count == 0)
            {
                cursor = consumed < 0 ? pos : consumed;
                return string.Join('.', labels).ToLowerInvariant();
            }
            if ((count & 0xc0) == 0xc0)
            {
                if (pos >= bytes.Length || ++jumps > 16) return null;
                if (consumed < 0) consumed = pos + 1;
                pos = ((count & 63) << 8) | bytes[pos];
                continue;
            }
            total += count + 1;
            if (count > 63 || count > bytes.Length - pos || total > 254) return null;
            labels.Add(Encoding.ASCII.GetString(bytes.Slice(pos, count))); pos += count;
        }
        return null;
    }
}
