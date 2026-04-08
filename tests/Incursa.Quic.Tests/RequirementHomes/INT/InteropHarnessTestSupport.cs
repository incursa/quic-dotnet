using System.Collections;

namespace Incursa.Quic.Tests;

internal sealed class TempDirectoryFixture : IDisposable
{
    public TempDirectoryFixture(string prefix)
    {
        RootDirectory = Path.Combine(Path.GetTempPath(), prefix, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(RootDirectory);
    }

    public string RootDirectory { get; }

    public string CreateFile(string fileName, string contents)
    {
        string path = Path.Combine(RootDirectory, fileName);
        File.WriteAllText(path, contents);
        return path;
    }

    public string CreateSubdirectory(string directoryName)
    {
        string path = Path.Combine(RootDirectory, directoryName);
        Directory.CreateDirectory(path);
        return path;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(RootDirectory))
            {
                Directory.Delete(RootDirectory, recursive: true);
            }
        }
        catch
        {
            // Best-effort cleanup only.
        }
    }
}

internal static class InteropHarnessTestSupport
{
    public static IDictionary CreateEnvironment(
        string role,
        string testcase,
        string? requests = null,
        string? qlogDir = null,
        string? sslKeyLogFile = null)
    {
        Hashtable environment = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ROLE"] = role,
            ["TESTCASE"] = testcase,
        };

        if (requests is not null)
        {
            environment["REQUESTS"] = requests;
        }

        if (qlogDir is not null)
        {
            environment["QLOGDIR"] = qlogDir;
        }

        if (sslKeyLogFile is not null)
        {
            environment["SSLKEYLOGFILE"] = sslKeyLogFile;
        }

        return environment;
    }

    public static (string CertificatePath, string PrivateKeyPath) CreateTlsMaterialFixture(TempDirectoryFixture fixture)
    {
        string certificatePath = fixture.CreateFile(
            "cert.pem",
            """
            -----BEGIN CERTIFICATE-----
            MIIB
            -----END CERTIFICATE-----
            """);

        string privateKeyPath = fixture.CreateFile(
            "priv.key",
            """
            -----BEGIN PRIVATE KEY-----
            MIIE
            -----END PRIVATE KEY-----
            """);

        return (certificatePath, privateKeyPath);
    }
}
