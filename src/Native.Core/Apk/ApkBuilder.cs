using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FlymeNative.Core;

public sealed record ApkBuildResult(string Path, long Length, string Sha256);

public static class ApkBuilder
{
    public static ApkBuildResult Build(string sourcePath, string outputPath, long targetSize, Action<string>? log = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(targetSize);
        if (targetSize >= uint.MaxValue) throw new ArgumentOutOfRangeException(nameof(targetSize), "ZIP32 APK must be smaller than 4 GiB.");
        var source = Path.GetFullPath(sourcePath);
        var destination = Path.GetFullPath(outputPath);
        if (string.Equals(source, destination, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Output must differ from the source APK.", nameof(outputPath));
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        var entries = ZipSource.Read(input);
        using var identity = SigningIdentity.Load();
        var directory = Path.GetDirectoryName(destination) ?? throw new ArgumentException("Output directory is missing.");
        var temporary = Path.Combine(directory, ".flyme-apk-" + Guid.NewGuid().ToString("N"));
        var unsigned = temporary + ".zip";
        try
        {
            log?.Invoke("APK: preserving payloads and creating JAR signature");
            using var archive = new FileStream(unsigned, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            var zip = new ZipOutput(archive);
            foreach (var entry in entries) zip.Copy(input, entry);
            foreach (var entry in JarSignature.Create(entries, identity)) zip.Add(entry.Name, entry.Bytes);
            var centralOffset = zip.Finish();
            archive.Flush();
            var signature = ApkV2Signature.Create(archive, centralOffset, identity);
            var padding = targetSize - archive.Length - signature.Length - 56;
            if (padding < 0) throw new InvalidDataException("Payloads, alignment and signatures exceed the requested size.");
            log?.Invoke("APK: creating v2 signature and exact-size padding");
            string sha256;
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                archive.Position = 0;
                ZipOutput.CopyBytes(archive, output, centralOffset);
                ApkV2Signature.WriteBlock(output, signature, padding);
                var finalCentralOffset = checked((uint)output.Position);
                archive.Position = centralOffset;
                ZipOutput.CopyBytes(archive, output, archive.Length - centralOffset - 22);
                var end = new byte[22];
                archive.ReadExactly(end);
                BinaryPrimitives.WriteUInt32LittleEndian(end.AsSpan(16), finalCentralOffset);
                output.Write(end);
                output.Flush(true);
                output.Position = 0;
                sha256 = Convert.ToHexString(SHA256.HashData(output)).ToLowerInvariant();
            }
            File.Move(temporary, destination, true);
            return new ApkBuildResult(destination, targetSize, sha256);
        }
        finally
        {
            File.Delete(temporary);
            File.Delete(unsigned);
        }
    }
}
