using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

public sealed class InteropTlsMaterialsTests
{
    [Fact]
    public void TryLoadReturnsFalseWhenTheCertificateFileIsMissing()
    {
        using TempDirectoryFixture fixture = new(nameof(InteropTlsMaterialsTests));

        string certificatePath = Path.Combine(fixture.RootDirectory, "missing-cert.pem");
        string privateKeyPath = fixture.CreateFile("priv.key", "unused");

        bool success = InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? errorMessage);

        Assert.False(success);
        Assert.Null(materials);
        Assert.Equal($"TLS certificate not found at '{certificatePath}'.", errorMessage);
    }

    [Fact]
    public void TryLoadReturnsFalseWhenThePrivateKeyFileIsMissing()
    {
        using TempDirectoryFixture fixture = new(nameof(InteropTlsMaterialsTests));

        string certificatePath = fixture.CreateFile("cert.pem", "unused");
        string privateKeyPath = Path.Combine(fixture.RootDirectory, "missing-key.pem");

        bool success = InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? errorMessage);

        Assert.False(success);
        Assert.Null(materials);
        Assert.Equal($"TLS private key not found at '{privateKeyPath}'.", errorMessage);
    }

    [Fact]
    public void TryCreateServerCertificateReturnsFalseWhenThePemContentIsInvalid()
    {
        using TempDirectoryFixture fixture = new(nameof(InteropTlsMaterialsTests));
        string certificatePath = fixture.CreateFile("cert.pem", "not-a-certificate");
        string privateKeyPath = fixture.CreateFile("priv.key", "not-a-private-key");

        Assert.True(
            InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? errorMessage),
            errorMessage ?? "TLS materials failed to load.");
        Assert.NotNull(materials);

        Assert.False(materials!.TryCreateServerCertificate(out X509Certificate2? certificate, out errorMessage));
        Assert.Null(certificate);
        Assert.StartsWith("Unable to create TLS server certificate:", errorMessage);
    }

    [Fact]
    public void TryCreateServerCertificateReturnsTheLoadedCertificateWhenThePemInputsAreValid()
    {
        using TempDirectoryFixture fixture = new(nameof(InteropTlsMaterialsTests));
        (string certificatePem, string privateKeyPem) = CreateServerCertificatePem("interop-tls-materials-tests");

        string certificatePath = fixture.CreateFile("cert.pem", certificatePem);
        string privateKeyPath = fixture.CreateFile("priv.key", privateKeyPem);

        Assert.True(
            InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? errorMessage),
            errorMessage ?? "TLS materials failed to load.");
        Assert.NotNull(materials);

        Assert.True(materials!.TryCreateServerCertificate(out X509Certificate2? certificate, out errorMessage), errorMessage ?? "TLS server certificate failed to load.");
        Assert.NotNull(certificate);

        using X509Certificate2 serverCertificate = certificate;

        Assert.True(serverCertificate.HasPrivateKey);
        Assert.Equal("CN=interop-tls-materials-tests", serverCertificate.Subject);
        Assert.NotNull(serverCertificate.GetECDsaPublicKey());
        Assert.NotNull(serverCertificate.GetECDsaPrivateKey());
    }

    private static (string CertificatePem, string PrivateKeyPem) CreateServerCertificatePem(string commonName)
    {
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            $"CN={commonName}",
            leafKey,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        return (certificate.ExportCertificatePem(), leafKey.ExportPkcs8PrivateKeyPem());
    }
}
