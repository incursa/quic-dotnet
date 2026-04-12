using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.InteropHarness;

internal sealed record InteropTlsMaterials(string CertificatePem, string PrivateKeyPem)
{
    public static bool TryLoad(InteropHarnessEnvironment environment, out InteropTlsMaterials? materials, out string? errorMessage)
    {
        return TryLoad(
            InteropHarnessEnvironment.CertificatePath,
            InteropHarnessEnvironment.PrivateKeyPath,
            out materials,
            out errorMessage);
    }

    internal static bool TryLoad(
        string certificatePath,
        string privateKeyPath,
        out InteropTlsMaterials? materials,
        out string? errorMessage)
    {
        materials = null;
        errorMessage = null;

        try
        {
            if (!File.Exists(certificatePath))
            {
                errorMessage = $"TLS certificate not found at '{certificatePath}'.";
                return false;
            }

            if (!File.Exists(privateKeyPath))
            {
                errorMessage = $"TLS private key not found at '{privateKeyPath}'.";
                return false;
            }

            materials = new InteropTlsMaterials(
                File.ReadAllText(certificatePath),
                File.ReadAllText(privateKeyPath));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            errorMessage = $"Unable to load TLS materials: {ex.Message}";
            return false;
        }
    }

    public bool TryCreateServerCertificate(out X509Certificate2? certificate, out string? errorMessage)
    {
        certificate = null;
        errorMessage = null;

        try
        {
            using X509Certificate2 certificateWithoutKey = X509Certificate2.CreateFromPem(CertificatePem);
            using ECDsa privateKey = ECDsa.Create();
            privateKey.ImportFromPem(PrivateKeyPem);
            using X509Certificate2 certificateWithKey = certificateWithoutKey.CopyWithPrivateKey(privateKey);
            byte[] pfxBytes = certificateWithKey.Export(X509ContentType.Pkcs12);
            certificate = X509CertificateLoader.LoadPkcs12(
                pfxBytes,
                (string?)null,
                X509KeyStorageFlags.Exportable);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or CryptographicException)
        {
            errorMessage = $"Unable to create TLS server certificate: {ex.Message}";
            return false;
        }
    }
}
