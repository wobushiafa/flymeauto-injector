using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using FlymeNative.Core;

if (args is ["build", var source, var buildOutput, var buildSize])
{
    Console.WriteLine(ApkBuilder.Build(source, buildOutput, long.Parse(buildSize), Console.WriteLine));
    return;
}

var root = Path.Combine(Path.GetTempPath(), "FlymeNative-ApkTests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
Console.WriteLine("ARTIFACTS: " + root);
var sdk = Environment.GetEnvironmentVariable("ANDROID_HOME") ?? throw new InvalidOperationException("Set ANDROID_HOME to your Android SDK directory before running APK verification.");
var tools = Path.Combine(sdk, "build-tools/36.1.0");
var manifest = Path.Combine(root, "AndroidManifest.xml");
File.WriteAllText(manifest, """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.flymenative.fixture" android:versionCode="1" android:versionName="1">
      <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28" />
      <application android:label="Native APK Test" android:hasCode="false" />
    </manifest>
    """);
var input = Path.Combine(root, "source.apk");
Run(Path.Combine(tools, "aapt2.exe"), ["link", "--manifest", manifest, "-I", Path.Combine(sdk, "platforms/android-36/android.jar"), "-o", input]);
using (var archive = ZipFile.Open(input, ZipArchiveMode.Update))
{
    Add(archive, "assets/" + new string('界', 45) + ".txt", Encoding.UTF8.GetBytes("unchanged UTF-8 asset"));
    Add(archive, "lib/arm64-v8a/libfixture.so", [0x7f, 0x45, 0x4c, 0x46, 7, 8, 9]);
    Add(archive, "META-INF/OLD.SF", "obsolete signature"u8.ToArray());
    Add(archive, "META-INF/OLD.RSA", "obsolete CMS"u8.ToArray());
}
var sourceHash = SHA256.HashData(File.ReadAllBytes(input));
var largeInput = Path.Combine(root, "multi-chunk-source.apk");
File.Copy(input, largeInput);
using (var archive = ZipFile.Open(largeInput, ZipArchiveMode.Update))
{
    Add(archive, "assets/multi-chunk.bin", RandomNumberGenerator.GetBytes(2 * 1024 * 1024 + 53));
    using var compressed = archive.CreateEntry("assets/compressed.bin", CompressionLevel.Optimal).Open();
    compressed.Write(new byte[1024 * 1024 + 17]);
}
foreach (var test in new[] { (Source: input, Size: 65537L, Name: "signed-65537"),
    (Source: input, Size: 27233004L, Name: "signed-27233004"),
    (Source: largeInput, Size: 27233004L, Name: "multi-chunk-27233004") })
{
    var output = Path.Combine(root, test.Name + ".apk");
    var result = ApkBuilder.Build(test.Source, output, test.Size, Console.WriteLine);
    Require(result.Length == test.Size && new FileInfo(output).Length == test.Size, "exact requested length");
    Require(result.Sha256 == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(output))).ToLowerInvariant(), "reported SHA256");
    var verification = Verify(output);
    Require(verification.Contains("Verified using v1 scheme (JAR signing): true", StringComparison.Ordinal), "official v1 verification");
    Require(verification.Contains("Verified using v2 scheme (APK Signature Scheme v2): true", StringComparison.Ordinal), "official v2 verification");
    using var original = ZipFile.OpenRead(test.Source);
    using var signed = ZipFile.OpenRead(output);
    foreach (var entry in original.Entries.Where(e => !e.FullName.StartsWith("META-INF/", StringComparison.Ordinal)))
    {
        using var oldStream = entry.Open();
        using var newStream = (signed.GetEntry(entry.FullName) ?? throw new Exception("missing payload")).Open();
        Require(SHA256.HashData(oldStream).SequenceEqual(SHA256.HashData(newStream)), "source payload retained: " + entry.FullName);
        ZipAssertions.CompareCompressed(test.Source, output, entry.FullName);
    }
    Require(signed.GetEntry("META-INF/OLD.SF") is null && signed.GetEntry("META-INF/OLD.RSA") is null, "obsolete signatures stripped");
    ZipAssertions.Check(output);
    var tampered = Path.Combine(root, "tampered-" + test.Name + ".apk");
    File.Copy(output, tampered);
    using (var stream = new FileStream(tampered, FileMode.Open, FileAccess.ReadWrite))
    {
        stream.Position = ZipAssertions.DataOffset(output, "lib/arm64-v8a/libfixture.so");
        stream.WriteByte(0);
    }
    var tamperResult = Run("java", ["-jar", Path.Combine(tools, "lib/apksigner.jar"), "verify", "--verbose", tampered], false);
    File.WriteAllText(tampered + ".verify.txt", tamperResult.Text);
    Require(tamperResult.ExitCode != 0, "official verifier rejects payload tamper");
    var v1Only = Run("java", ["-jar", Path.Combine(tools, "lib/apksigner.jar"), "verify", "--verbose", "--min-sdk-version", "23", "--max-sdk-version", "23", output]);
    Require(v1Only.Text.Contains("Verified using v1 scheme (JAR signing): true", StringComparison.Ordinal), "v1 verifies on pre-v2 Android API 23");
    Console.WriteLine(Run(Path.Combine(tools, "zipalign.exe"), ["-c", "-P", "16", "-v", "4", output]).Text);
}
Require(sourceHash.SequenceEqual(SHA256.HashData(File.ReadAllBytes(input))), "source bytes untouched");
var rebuilt = Path.Combine(root, "resigned.apk");
File.WriteAllText(rebuilt, "previous output");
ApkBuilder.Build(Path.Combine(root, "signed-65537.apk"), rebuilt, 65537);
Require(Verify(rebuilt).Contains("Verified using v2 scheme (APK Signature Scheme v2): true", StringComparison.Ordinal), "re-sign existing APK");
Require(SHA256.HashData(File.ReadAllBytes(rebuilt)).SequenceEqual(SHA256.HashData(File.ReadAllBytes(Path.Combine(root, "signed-65537.apk")))) , "persistent identity produces identical rebuilt APK");
foreach (var target in new long[] { -1, 100, (long)uint.MaxValue + 1 })
    Reject(() => ApkBuilder.Build(input, Path.Combine(root, "rejected.apk"), target));
Reject(() => ApkBuilder.Build(input, input, 65537));
var invalid = Path.Combine(root, "invalid.apk");
File.WriteAllText(invalid, "invalid ZIP");
Reject(() => ApkBuilder.Build(invalid, Path.Combine(root, "invalid-output.apk"), 65537));
var missingManifest = Path.Combine(root, "missing-manifest.apk");
using (var archive = ZipFile.Open(missingManifest, ZipArchiveMode.Create)) Add(archive, "only.txt", "payload"u8.ToArray());
Reject(() => ApkBuilder.Build(missingManifest, Path.Combine(root, "missing-output.apk"), 65537));
var textManifest = Path.Combine(root, "text-manifest.apk");
using (var archive = ZipFile.Open(textManifest, ZipArchiveMode.Create)) Add(archive, "AndroidManifest.xml", "<manifest/>"u8.ToArray());
Reject(() => ApkBuilder.Build(textManifest, Path.Combine(root, "text-output.apk"), 65537));
Reject(() => ApkBuilder.Build(Path.Combine(root, "tampered-signed-65537.apk"), Path.Combine(root, "corrupt-output.apk"), 65537));
var preserved = Path.Combine(root, "preserved.apk");
File.WriteAllText(preserved, "keep me");
Reject(() => ApkBuilder.Build(input, preserved, 100));
Require(File.ReadAllText(preserved) == "keep me", "failed build preserves destination");
Console.WriteLine("PASS: exact sizing, SHA256, payload preservation, alignment, v1/v2 verification, tamper rejection, re-signing, invalid inputs, atomic failure");

string Verify(string path)
{
    var result = Run("java", ["-jar", Path.Combine(tools, "lib/apksigner.jar"), "verify", "--verbose", "--print-certs", path]);
    File.WriteAllText(path + ".verify.txt", result.Text);
    Console.WriteLine(result.Text);
    return result.Text;
}

static void Add(ZipArchive archive, string name, byte[] bytes)
{
    using var stream = archive.CreateEntry(name, CompressionLevel.NoCompression).Open();
    stream.Write(bytes);
}

static (int ExitCode, string Text) Run(string executable, string[] arguments, bool success = true)
{
    var info = new ProcessStartInfo(executable) { RedirectStandardOutput = true, RedirectStandardError = true };
    foreach (var argument in arguments) info.ArgumentList.Add(argument);
    using var process = Process.Start(info) ?? throw new Exception("Cannot start " + executable);
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(60000)) { process.Kill(true); throw new Exception("Tool timed out"); }
    var text = stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult();
    if (success && process.ExitCode != 0) throw new Exception(text);
    return (process.ExitCode, text);
}

static void Require(bool condition, string contract)
{
    if (!condition) throw new Exception("FAIL: " + contract);
}

static void Reject(Action action)
{
    try { action(); }
    catch (Exception error) when (error is ArgumentException or InvalidDataException or IOException) { return; }
    throw new Exception("FAIL: invalid build accepted");
}
