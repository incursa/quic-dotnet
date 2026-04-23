namespace Incursa.Quic;

/// <summary>
/// Owns connection-local 1-RTT key-update epoch facts that must survive beyond the TLS bridge publication.
/// </summary>
internal sealed class QuicOneRttKeyUpdateLifecycle
{
    private QuicTlsPacketProtectionMaterial? retainedOldOpenPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial? retainedOldProtectPacketProtectionMaterial;

    internal QuicTlsPacketProtectionMaterial? RetainedOldOpenPacketProtectionMaterial =>
        retainedOldOpenPacketProtectionMaterial;

    internal QuicTlsPacketProtectionMaterial? RetainedOldProtectPacketProtectionMaterial =>
        retainedOldProtectPacketProtectionMaterial;

    internal bool HasRetainedOldPacketProtectionMaterial =>
        retainedOldOpenPacketProtectionMaterial.HasValue
        || retainedOldProtectPacketProtectionMaterial.HasValue;

    internal bool TryRetainOldPacketProtectionMaterial(
        QuicTlsPacketProtectionMaterial openMaterial,
        QuicTlsPacketProtectionMaterial protectMaterial)
    {
        if (HasRetainedOldPacketProtectionMaterial
            || openMaterial.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt
            || protectMaterial.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt)
        {
            return false;
        }

        retainedOldOpenPacketProtectionMaterial = openMaterial;
        retainedOldProtectPacketProtectionMaterial = protectMaterial;
        return true;
    }

    internal bool TryDiscardRetainedOldPacketProtectionMaterial()
    {
        if (!HasRetainedOldPacketProtectionMaterial)
        {
            return false;
        }

        Reset();
        return true;
    }

    internal void Reset()
    {
        retainedOldOpenPacketProtectionMaterial = null;
        retainedOldProtectPacketProtectionMaterial = null;
    }
}
