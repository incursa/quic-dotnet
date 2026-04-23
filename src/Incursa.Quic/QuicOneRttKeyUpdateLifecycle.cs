namespace Incursa.Quic;

/// <summary>
/// Owns connection-local 1-RTT key-update epoch facts that must survive beyond the TLS bridge publication.
/// </summary>
internal sealed class QuicOneRttKeyUpdateLifecycle
{
    private QuicTlsPacketProtectionMaterial? retainedOldOpenPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial? retainedOldProtectPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial? retainedNextOpenPacketProtectionMaterial;

    internal QuicTlsPacketProtectionMaterial? RetainedOldOpenPacketProtectionMaterial =>
        retainedOldOpenPacketProtectionMaterial;

    internal QuicTlsPacketProtectionMaterial? RetainedOldProtectPacketProtectionMaterial =>
        retainedOldProtectPacketProtectionMaterial;

    internal QuicTlsPacketProtectionMaterial? RetainedNextOpenPacketProtectionMaterial =>
        retainedNextOpenPacketProtectionMaterial;

    internal bool HasRetainedOldPacketProtectionMaterial =>
        retainedOldOpenPacketProtectionMaterial.HasValue
        || retainedOldProtectPacketProtectionMaterial.HasValue;

    internal bool HasRetainedNextOpenPacketProtectionMaterial =>
        retainedNextOpenPacketProtectionMaterial.HasValue;

    internal bool HasPacketProtectionMaterial =>
        HasRetainedOldPacketProtectionMaterial
        || HasRetainedNextOpenPacketProtectionMaterial;

    internal bool CanCommitNextOpenPacketProtectionMaterial(QuicTlsPacketProtectionMaterial openMaterial)
    {
        return !retainedNextOpenPacketProtectionMaterial.HasValue
            || retainedNextOpenPacketProtectionMaterial.Value.Matches(openMaterial);
    }

    internal void ClearRetainedNextOpenPacketProtectionMaterial()
    {
        retainedNextOpenPacketProtectionMaterial = null;
    }

    internal bool TryRetainNextOpenPacketProtectionMaterial(
        QuicTlsPacketProtectionMaterial currentOpenMaterial,
        QuicTlsPacketProtectionMaterial nextOpenMaterial)
    {
        if (HasRetainedNextOpenPacketProtectionMaterial
            || currentOpenMaterial.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt
            || nextOpenMaterial.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt
            || currentOpenMaterial.Matches(nextOpenMaterial))
        {
            return false;
        }

        retainedNextOpenPacketProtectionMaterial = nextOpenMaterial;
        return true;
    }

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
        retainedNextOpenPacketProtectionMaterial = null;
    }
}
