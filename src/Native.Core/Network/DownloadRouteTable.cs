using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace FlymeNative.Core;

// State is shared by the DNS worker and the two TCP workers. Authorization is
// recorded before the DNS answer is sent; only a new SYN can create a mapping.
internal sealed class DownloadRouteTable(HotspotInfo hotspot, IPAddress publicAddress, Func<long>? clock = null)
{
    private readonly object gate = new();
    private readonly Dictionary<uint, long> clients = [];
    private readonly Dictionary<(uint Client, ushort Port, ushort Service), long> flows = [];
    private readonly Func<long> now = clock ?? (() => Environment.TickCount64);
    private readonly uint gateway = Number(hotspot.Address);
    private readonly uint destination = Number(publicAddress);
    private readonly WindowsSubnet subnet = WindowsSubnet.From(hotspot);
    private const long Lifetime = 15 * 60 * 1000;

    internal void Authorize(IPAddress client)
    {
        uint address = Number(client);
        if (address <= subnet.Network || address >= subnet.Broadcast || address == gateway)
            throw new ArgumentException("DNS client is outside the hotspot subnet.", nameof(client));
        lock (gate)
        {
            Prune();
            if (clients.Count >= 4096 && !clients.ContainsKey(address)) throw new InvalidOperationException("热点客户端记录已满。");
            clients[address] = now();
        }
    }

    internal bool Translate(Span<byte> packet, bool returning)
    {
        if (packet.Length < 40 || packet[0] >> 4 != 4 || packet[9] != 6 ||
            BinaryPrimitives.ReadUInt16BigEndian(packet[2..]) != packet.Length ||
            (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3fff) != 0) return false;
        int ihl = (packet[0] & 15) * 4;
        if (ihl < 20 || ihl + 20 > packet.Length || (packet[ihl + 12] >> 4) * 4 < 20 ||
            ihl + (packet[ihl + 12] >> 4) * 4 > packet.Length) return false;
        uint source = BinaryPrimitives.ReadUInt32BigEndian(packet[12..]), target = BinaryPrimitives.ReadUInt32BigEndian(packet[16..]);
        ushort sourcePort = BinaryPrimitives.ReadUInt16BigEndian(packet[ihl..]), targetPort = BinaryPrimitives.ReadUInt16BigEndian(packet[(ihl + 2)..]);
        uint client = returning ? target : source;
        ushort port = returning ? targetPort : sourcePort, service = returning ? sourcePort : targetPort;
        if (service is not (80 or 443) || (returning ? source != gateway : target != destination)) return false;
        var key = (client, port, service);
        lock (gate)
        {
            long timestamp = now();
            if (!flows.TryGetValue(key, out long seen) || timestamp - seen > Lifetime)
            {
                if (returning || (packet[ihl + 13] & 0x17) != 2 ||
                    !clients.TryGetValue(client, out long authorized) || timestamp - authorized > Lifetime) return false;
                Prune();
                if (flows.Count >= 8192) throw new InvalidOperationException("下载连接记录已满，请停止服务后重试。");
            }
            flows[key] = timestamp;
        }
        BinaryPrimitives.WriteUInt32BigEndian(packet[(returning ? 12 : 16)..], returning ? destination : gateway);
        return true;
    }

    private void Prune()
    {
        long oldest = now() - Lifetime;
        foreach (var key in clients.Where(pair => pair.Value < oldest).Select(pair => pair.Key).ToArray()) clients.Remove(key);
        foreach (var key in flows.Where(pair => pair.Value < oldest).Select(pair => pair.Key).ToArray()) flows.Remove(key);
    }

    internal static bool IsPublic(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        byte[] b = address.GetAddressBytes();
        return b[0] is > 0 and < 224 && b[0] is not (10 or 127) &&
            !(b[0] == 169 && b[1] == 254) && !(b[0] == 172 && b[1] is >= 16 and <= 31) &&
            !(b[0] == 192 && b[1] == 168) && !(b[0] == 100 && b[1] is >= 64 and <= 127) &&
            !(b[0] == 198 && b[1] is 18 or 19);
    }

    private static uint Number(IPAddress address) => address.AddressFamily == AddressFamily.InterNetwork
        ? BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes()) : throw new ArgumentException("IPv4 required.");
}
