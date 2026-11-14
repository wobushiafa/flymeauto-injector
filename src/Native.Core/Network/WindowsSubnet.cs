using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace FlymeNative.Core;

public sealed record HotspotInfo(int InterfaceIndex, string Name, IPAddress Address, int PrefixLength);

internal readonly record struct WindowsSubnet(uint Network, uint Broadcast)
{
    internal static WindowsSubnet From(HotspotInfo hotspot)
    {
        ArgumentNullException.ThrowIfNull(hotspot);
        if (hotspot.InterfaceIndex <= 0 || hotspot.Address.AddressFamily != AddressFamily.InterNetwork ||
            hotspot.PrefixLength is < 1 or > 30)
            throw new ArgumentException("Hotspot requires a valid IPv4 interface and a client subnet prefix between 1 and 30.", nameof(hotspot));
        uint address = BinaryPrimitives.ReadUInt32BigEndian(hotspot.Address.GetAddressBytes());
        uint mask = uint.MaxValue << (32 - hotspot.PrefixLength);
        uint network = address & mask, broadcast = network | ~mask;
        if (address == network || address == broadcast)
            throw new ArgumentException("Hotspot gateway must be a host address.", nameof(hotspot));
        return new(network, broadcast);
    }

    internal string ClientFilter(HotspotInfo hotspot) =>
        $"ip and udp and udp.DstPort == 53 and !impostor and ip.SrcAddr > {Format(Network)} and ip.SrcAddr < {Format(Broadcast)} and ip.SrcAddr != {hotspot.Address}";

    internal static string Format(uint address)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, address);
        return new IPAddress(bytes).ToString();
    }
}
