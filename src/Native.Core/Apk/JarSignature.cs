using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FlymeNative.Core;

internal static class JarSignature
{
    public static IReadOnlyList<(string Name, byte[] Bytes)> Create(IReadOnlyList<ZipPayload> entries, X509Certificate2 certificate)
    {
        using var manifest = new MemoryStream();
        manifest.Write("Manifest-Version: 1.0\r\nCreated-By: FlymeNative\r\n\r\n"u8);
        var sections = new List<(string Name, byte[] Bytes)>();
        foreach (var entry in entries.Where(e => !e.Name.EndsWith('/')))
        {
            using var section = new MemoryStream();
            Header(section, "Name", entry.Name);
            Header(section, "SHA-256-Digest", Convert.ToBase64String(entry.Digest));
            section.Write("\r\n"u8);
            var bytes = section.ToArray();
            sections.Add((entry.Name, bytes));
            manifest.Write(bytes);
        }
        var manifestBytes = manifest.ToArray();
        using var sf = new MemoryStream();
        Header(sf, "Signature-Version", "1.0");
        Header(sf, "Created-By", "FlymeNative");
        Header(sf, "X-Android-APK-Signed", "2");
        Header(sf, "SHA-256-Digest-Manifest", Convert.ToBase64String(SHA256.HashData(manifestBytes)));
        sf.Write("\r\n"u8);
        foreach (var section in sections)
        {
            Header(sf, "Name", section.Name);
            Header(sf, "SHA-256-Digest", Convert.ToBase64String(SHA256.HashData(section.Bytes)));
            sf.Write("\r\n"u8);
        }
        var sfBytes = sf.ToArray();
        return [("META-INF/MANIFEST.MF", manifestBytes), ("META-INF/FLYME.SF", sfBytes), ("META-INF/FLYME.RSA", Cms(sfBytes, certificate))];
    }

    private static void Header(Stream stream, string name, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(name + ": " + value);
        var offset = 0;
        while (offset < bytes.Length)
        {
            // JAR physical lines are at most 72 bytes, excluding CRLF. Never split a UTF-8 scalar.
            var count = Math.Min(offset == 0 ? 72 : 71, bytes.Length - offset);
            while (offset + count < bytes.Length && (bytes[offset + count] & 0xc0) == 0x80) count--;
            if (offset > 0) stream.WriteByte(32);
            stream.Write(bytes.AsSpan(offset, count));
            stream.Write("\r\n"u8);
            offset += count;
        }
    }

    private static byte[] Cms(byte[] content, X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPrivateKey() ?? throw new CryptographicException("Signing certificate has no RSA key.");
        var signature = rsa.SignData(content, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        var explicitZero = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
        writer.PushSequence(explicitZero);
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.PushSetOf();
        Algorithm(writer, "2.16.840.1.101.3.4.2.1");
        writer.PopSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.1");
        writer.PopSequence();
        writer.PushSetOf(explicitZero);
        writer.WriteEncodedValue(certificate.RawData);
        writer.PopSetOf(explicitZero);
        writer.PushSetOf();
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.PushSequence();
        writer.WriteEncodedValue(certificate.IssuerName.RawData);
        writer.WriteIntegerUnsigned(certificate.SerialNumberBytes.Span);
        writer.PopSequence();
        Algorithm(writer, "2.16.840.1.101.3.4.2.1");
        Algorithm(writer, "1.2.840.113549.1.1.1");
        writer.WriteOctetString(signature);
        writer.PopSequence();
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence(explicitZero);
        writer.PopSequence();
        return writer.Encode();
    }

    private static void Algorithm(AsnWriter writer, string oid)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(oid);
        writer.WriteNull();
        writer.PopSequence();
    }
}
