using System.ComponentModel;
using System.Runtime.InteropServices;

namespace FlymeNative.Core;

[StructLayout(LayoutKind.Explicit, Size = 80)]
internal struct WinDivertAddress
{
    [FieldOffset(0)] internal long Timestamp;
    [FieldOffset(8)] internal uint Flags;
    [FieldOffset(12)] internal uint Reserved;
    [FieldOffset(16)] internal uint InterfaceIndex;
    [FieldOffset(20)] internal uint SubInterfaceIndex;
}

internal static unsafe class WinDivertNative
{
    private const string Library = "WinDivert64.dll";

    [DllImport(Library, EntryPoint = "WinDivertOpen", ExactSpelling = true, SetLastError = true)]
    internal static extern nint Open([MarshalAs(UnmanagedType.LPStr)] string filter, int layer, short priority, ulong flags);

    [DllImport(Library, EntryPoint = "WinDivertRecv", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Receive(nint handle, byte* packet, uint capacity, out uint length, out WinDivertAddress address);

    [DllImport(Library, EntryPoint = "WinDivertSend", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Send(nint handle, byte* packet, uint length, out uint sent, in WinDivertAddress address);

    [DllImport(Library, EntryPoint = "WinDivertShutdown", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Shutdown(nint handle, int how);

    [DllImport(Library, EntryPoint = "WinDivertClose", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Close(nint handle);

    [DllImport(Library, EntryPoint = "WinDivertHelperCalcChecksums", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CalculateChecksums(byte* packet, uint length, ref WinDivertAddress address, ulong flags);

    [DllImport(Library, EntryPoint = "WinDivertHelperCompileFilter", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CompileFilter([MarshalAs(UnmanagedType.LPStr)] string filter, int layer,
        nint buffer, uint capacity, out nint error, out uint position);

    [DllImport(Library, EntryPoint = "WinDivertHelperEvalFilter", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool EvaluateFilter([MarshalAs(UnmanagedType.LPStr)] string filter, byte* packet,
        uint length, in WinDivertAddress address);

    internal static nint OpenChecked(string filter, int layer, ulong flags)
    {
        nint handle = Open(filter, layer, -100, flags);
        if (handle == -1) throw new Win32Exception(Marshal.GetLastPInvokeError(), $"WinDivertOpen layer {layer} failed. Administrator rights and bundled signed WinDivert driver are required.");
        return handle;
    }
}
