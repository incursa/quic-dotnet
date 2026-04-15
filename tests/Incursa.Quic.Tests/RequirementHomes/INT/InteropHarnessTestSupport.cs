using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Incursa.Quic.InteropHarness;

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
    private static readonly SemaphoreSlim HarnessCertificateGate = new(1, 1);

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

    public static async Task WithHarnessCertificateAsync(string dnsName, Func<Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);

        await HarnessCertificateGate.WaitAsync().ConfigureAwait(false);

        string certPath = Path.GetFullPath(InteropHarnessEnvironment.CertificatePath);
        string privateKeyPath = Path.GetFullPath(InteropHarnessEnvironment.PrivateKeyPath);
        string? originalCertificatePem = File.Exists(certPath) ? File.ReadAllText(certPath) : null;
        string? originalPrivateKeyPem = File.Exists(privateKeyPath) ? File.ReadAllText(privateKeyPath) : null;

        try
        {
            using X509Certificate2 certificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate(dnsName);
            using ECDsa? privateKey = certificate.GetECDsaPrivateKey();

            if (privateKey is null)
            {
                throw new InvalidOperationException("Unable to acquire the harness TLS private key.");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(certPath)!);
            File.WriteAllText(certPath, certificate.ExportCertificatePem());
            File.WriteAllText(privateKeyPath, privateKey.ExportPkcs8PrivateKeyPem());

            await action().ConfigureAwait(false);
        }
        finally
        {
            try
            {
                if (originalCertificatePem is null)
                {
                    if (File.Exists(certPath))
                    {
                        File.Delete(certPath);
                    }
                }
                else
                {
                    File.WriteAllText(certPath, originalCertificatePem);
                }
            }
            finally
            {
                try
                {
                    if (originalPrivateKeyPem is null)
                    {
                        if (File.Exists(privateKeyPath))
                        {
                            File.Delete(privateKeyPath);
                        }
                    }
                    else
                    {
                        File.WriteAllText(privateKeyPath, originalPrivateKeyPem);
                    }
                }
                finally
                {
                    HarnessCertificateGate.Release();
                }
            }
        }
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
