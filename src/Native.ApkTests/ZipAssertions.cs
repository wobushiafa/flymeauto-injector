using System.Text;

internal static class ZipAssertions
{
    public static long DataOffset(string path, string name) => Locate(path, name).Offset;

    public static void CompareCompressed(string source, string output, string name)
    {
        using var original = System.IO.Compression.ZipFile.OpenRead(source);
        var length = (original.GetEntry(name) ?? throw new Exception("Missing entry")).CompressedLength;
        using var oldBytes = File.OpenRead(source);
        using var newBytes = File.OpenRead(output);
        oldBytes.Position = DataOffset(source, name);
        newBytes.Position = DataOffset(output, name);
        var left = new byte[checked((int)length)];
        var right = new byte[left.Length];
        oldBytes.ReadExactly(left);
        newBytes.ReadExactly(right);
        if (!left.SequenceEqual(right)) throw new Exception("Compressed bytes changed: " + name);
    }

    private static (long Offset, ushort Method) Locate(string path, string name)
    {
        using var stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream, Encoding.UTF8);
        while (reader.ReadUInt32() == 0x04034b50)
        {
            stream.Position += 4;
            var method = reader.ReadUInt16();
            stream.Position += 8;
            var size = reader.ReadUInt32();
            stream.Position += 4;
            var nameLength = reader.ReadUInt16();
            var extraLength = reader.ReadUInt16();
            var entryName = Encoding.UTF8.GetString(reader.ReadBytes(nameLength));
            stream.Position += extraLength;
            if (entryName == name) return (stream.Position, method);
            stream.Position += size;
        }
        throw new Exception("Missing ZIP local entry: " + name);
    }

    public static void Check(string path)
    {
        using var archive = System.IO.Compression.ZipFile.OpenRead(path);
        foreach (var entry in archive.Entries)
        {
            var (offset, method) = Locate(path, entry.FullName);
            var alignment = entry.FullName.EndsWith(".so", StringComparison.Ordinal) ? 16384 : 4;
            if (method == 0 && offset % alignment != 0) throw new Exception("Misaligned payload: " + entry.FullName);
        }
        foreach (var name in new[] { "META-INF/MANIFEST.MF", "META-INF/FLYME.SF" })
        {
            using var text = (archive.GetEntry(name) ?? throw new Exception("Missing JAR metadata")).Open();
            using var reader = new StreamReader(text, new UTF8Encoding(false, true));
            string? line;
            while ((line = reader.ReadLine()) is not null)
                if (Encoding.UTF8.GetByteCount(line) > 72) throw new Exception("JAR line exceeds 72 bytes");
        }
    }
}
