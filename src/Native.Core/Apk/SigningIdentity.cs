using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FlymeNative.Core;

internal static class SigningIdentity
{
    public static X509Certificate2 Load()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FlymeNative");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "apk-signing.pfx");
        if (!File.Exists(path))
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=Flyme Native APK", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(30));
            var temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                File.WriteAllBytes(temporary, certificate.Export(X509ContentType.Pfx, ""));
                try { File.Move(temporary, path); }
                catch (IOException) when (File.Exists(path)) { /* A simultaneous builder published the shared identity. */ }
            }
            finally { File.Delete(temporary); }
        }
        return X509CertificateLoader.LoadPkcs12FromFile(path, "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }
}
