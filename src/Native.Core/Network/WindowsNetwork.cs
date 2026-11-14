using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace FlymeNative.Core;

public static unsafe class WindowsNetwork
{
    public static bool IsAdministrator
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            Span<byte> sid = stackalloc byte[68];
            uint length = (uint)sid.Length;
            fixed (byte* pointer = sid)
            {
                if (!CreateWellKnownSid(26, 0, pointer, ref length) ||
                    !CheckTokenMembership(0, pointer, out bool member))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "Cannot determine administrator token membership.");
                return member;
            }
        }
    }

    public static HotspotInfo DiscoverHotspot()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows hotspot discovery requires Windows.");
        HashSet<uint> directInterfaces = WindowsAdapters.ActiveWifiDirectIndices();
        var candidates = new List<HotspotInfo>();
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up || !adapter.Supports(NetworkInterfaceComponent.IPv4)) continue;
            IPInterfaceProperties properties = adapter.GetIPProperties();
            int index = properties.GetIPv4Properties().Index;
            if (!directInterfaces.Contains((uint)index)) continue;
            foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork || unicast.PrefixLength is < 1 or > 30) continue;
                byte[] bytes = unicast.Address.GetAddressBytes();
                bool isPrivate = bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                    (bytes[0] == 192 && bytes[1] == 168);
                if (isPrivate && unicast.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Preferred)
                    candidates.Add(new(index, adapter.Name, unicast.Address, unicast.PrefixLength));
            }
        }
        if (candidates.Count != 1)
            throw new InvalidOperationException($"Hotspot discovery found {candidates.Count} usable addresses on active native Wi-Fi Direct adapters. Enable Windows Mobile Hotspot with IPv4 sharing; multiple candidates must be resolved explicitly.");
        _ = WindowsSubnet.From(candidates[0]);
        return candidates[0];
    }

    public static IDisposable AllowDownloads(HotspotInfo hotspot)
    {
        _ = WindowsSubnet.From(hotspot);
        if (!OperatingSystem.IsWindows() || !IsAdministrator)
            throw new InvalidOperationException("Scoped Windows Firewall setup requires Windows administrator rights.");
        return WindowsFirewall.Create(hotspot);
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateWellKnownSid(int type, nint domain, byte* sid, ref uint size);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CheckTokenMembership(nint token, byte* sid, [MarshalAs(UnmanagedType.Bool)] out bool member);
}
