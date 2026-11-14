using System.ComponentModel;
using System.Runtime.InteropServices;

namespace FlymeNative.Core;

internal static unsafe class WindowsAdapters
{
    [StructLayout(LayoutKind.Explicit, Size = 112)]
    private struct AdapterHeader
    {
        [FieldOffset(0)] internal uint Length;
        [FieldOffset(4)] internal uint InterfaceIndex;
        [FieldOffset(8)] internal nint Next;
        [FieldOffset(64)] internal nint Description;
        [FieldOffset(100)] internal uint InterfaceType;
        [FieldOffset(104)] internal uint OperationalStatus;
    }

    internal static HashSet<uint> ActiveWifiDirectIndices()
    {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("Native adapter discovery requires Windows x64.");
        uint size = 16384;
        for (int attempt = 0; attempt < 4; attempt++)
        {
            if (size > 4 * 1024 * 1024) throw new InvalidOperationException("Native adapter enumeration exceeded its buffer limit.");
            nint buffer = Marshal.AllocHGlobal(checked((int)size));
            try
            {
                uint result = GetAdaptersAddresses(2, 0x10, 0, buffer, ref size);
                if (result == 111) continue;
                if (result == 232) return [];
                if (result != 0) throw new Win32Exception((int)result, "GetAdaptersAddresses failed.");
                var indices = new HashSet<uint>();
                for (nint current = buffer; current != 0;)
                {
                    AdapterHeader adapter = *(AdapterHeader*)current;
                    if (adapter.Length < 108) throw new InvalidOperationException("Unsupported native adapter structure version.");
                    string description = Marshal.PtrToStringUni(adapter.Description) ?? string.Empty;
                    if (adapter.OperationalStatus == 1 && adapter.InterfaceType == 71 &&
                        (description.Contains("Wi-Fi Direct", StringComparison.OrdinalIgnoreCase) ||
                         description.Contains("WiFi Direct", StringComparison.OrdinalIgnoreCase)))
                        indices.Add(adapter.InterfaceIndex);
                    current = adapter.Next;
                }
                return indices;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidOperationException("Network adapters changed repeatedly during hotspot discovery.");
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetAdaptersAddresses(uint family, uint flags, nint reserved, nint adapters, ref uint size);
}
