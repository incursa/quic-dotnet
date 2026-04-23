using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Carries a pending 1-RTT traffic-secret successor until the matching key-update commit succeeds.
/// </summary>
internal sealed class QuicOneRttTrafficSecretUpdate : IDisposable
{
    private byte[]? clientApplicationTrafficSecret;
    private byte[]? serverApplicationTrafficSecret;

    internal QuicOneRttTrafficSecretUpdate(
        byte[] clientApplicationTrafficSecret,
        byte[] serverApplicationTrafficSecret,
        QuicTlsPacketProtectionMaterial openPacketProtectionMaterial,
        QuicTlsPacketProtectionMaterial protectPacketProtectionMaterial)
    {
        this.clientApplicationTrafficSecret = clientApplicationTrafficSecret;
        this.serverApplicationTrafficSecret = serverApplicationTrafficSecret;
        OpenPacketProtectionMaterial = openPacketProtectionMaterial;
        ProtectPacketProtectionMaterial = protectPacketProtectionMaterial;
    }

    internal QuicTlsPacketProtectionMaterial OpenPacketProtectionMaterial { get; }

    internal QuicTlsPacketProtectionMaterial ProtectPacketProtectionMaterial { get; }

    internal bool TryTakeApplicationTrafficSecrets(
        out byte[] clientApplicationTrafficSecret,
        out byte[] serverApplicationTrafficSecret)
    {
        clientApplicationTrafficSecret = [];
        serverApplicationTrafficSecret = [];

        if (this.clientApplicationTrafficSecret is null
            || this.serverApplicationTrafficSecret is null)
        {
            return false;
        }

        clientApplicationTrafficSecret = this.clientApplicationTrafficSecret;
        serverApplicationTrafficSecret = this.serverApplicationTrafficSecret;
        this.clientApplicationTrafficSecret = null;
        this.serverApplicationTrafficSecret = null;
        return true;
    }

    public void Dispose()
    {
        if (clientApplicationTrafficSecret is not null)
        {
            CryptographicOperations.ZeroMemory(clientApplicationTrafficSecret);
            clientApplicationTrafficSecret = null;
        }

        if (serverApplicationTrafficSecret is not null)
        {
            CryptographicOperations.ZeroMemory(serverApplicationTrafficSecret);
            serverApplicationTrafficSecret = null;
        }
    }
}
