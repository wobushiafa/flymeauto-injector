using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

Console.WriteLine("Hello from .NET 10 NativeAOT!");
Console.WriteLine($"Architecture: {RuntimeInformation.ProcessArchitecture}");
Console.WriteLine($"Dynamic code supported: {RuntimeFeature.IsDynamicCodeSupported}");
return RuntimeFeature.IsDynamicCodeSupported ? 1 : 0;
