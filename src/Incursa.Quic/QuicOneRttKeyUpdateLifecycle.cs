namespace Incursa.Quic;

/// <summary>
/// Owns connection-local 1-RTT key-update epoch facts that must survive beyond the TLS bridge publication.
/// </summary>
internal sealed class QuicOneRttKeyUpdateLifecycle
{
    private const ulong ThreePtoMultiplier = 3;

    private QuicTlsPacketProtectionMaterial? retainedOldOpenPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial? retainedOldProtectPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial? retainedNextOpenPacketProtectionMaterial;
    private ulong? retainedOldPacketProtectionDiscardAtMicros;
    private ulong? retainedOldPacketProtectionKeyPhase;
    private ulong? repeatedLocalPacketProtectionUpdateNotBeforeMicros;
    private ulong? acknowledgedCurrentPacketProtectionKeyPhase;

    internal QuicTlsPacketProtectionMaterial? RetainedOldOpenPacketProtectionMaterial =>
        retainedOldOpenPacketProtectionMaterial;

    internal QuicTlsPacketProtectionMaterial? RetainedOldProtectPacketProtectionMaterial =>
        retainedOldProtectPacketProtectionMaterial;

    internal QuicTlsPacketProtectionMaterial? RetainedNextOpenPacketProtectionMaterial =>
        retainedNextOpenPacketProtectionMaterial;

    internal ulong? RetainedOldPacketProtectionDiscardAtMicros =>
        retainedOldPacketProtectionDiscardAtMicros;

    internal ulong? RetainedOldPacketProtectionKeyPhase =>
        retainedOldPacketProtectionKeyPhase;

    internal ulong? RepeatedLocalPacketProtectionUpdateNotBeforeMicros =>
        repeatedLocalPacketProtectionUpdateNotBeforeMicros;

    internal bool CurrentPacketProtectionPhaseAcknowledged =>
        acknowledgedCurrentPacketProtectionKeyPhase.HasValue;

    internal bool HasRetainedOldPacketProtectionMaterial =>
        retainedOldOpenPacketProtectionMaterial.HasValue
        || retainedOldProtectPacketProtectionMaterial.HasValue;

    internal bool HasRetainedNextOpenPacketProtectionMaterial =>
        retainedNextOpenPacketProtectionMaterial.HasValue;

    internal bool HasRetainedOldPacketProtectionDiscardDeadline =>
        retainedOldPacketProtectionDiscardAtMicros.HasValue;

    internal bool HasPacketProtectionMaterial =>
        HasRetainedOldPacketProtectionMaterial
        || HasRetainedNextOpenPacketProtectionMaterial;

    internal bool CanInitiateRepeatedLocalPacketProtectionUpdate(ulong keyPhase, ulong nowMicros)
    {
        return repeatedLocalPacketProtectionUpdateNotBeforeMicros.HasValue
            && acknowledgedCurrentPacketProtectionKeyPhase.HasValue
            && acknowledgedCurrentPacketProtectionKeyPhase.Value == keyPhase
            && nowMicros >= repeatedLocalPacketProtectionUpdateNotBeforeMicros.Value;
    }

    internal bool CanCommitNextOpenPacketProtectionMaterial(QuicTlsPacketProtectionMaterial openMaterial)
    {
        return !retainedNextOpenPacketProtectionMaterial.HasValue
            || retainedNextOpenPacketProtectionMaterial.Value.Matches(openMaterial);
    }

    internal void ClearRetainedNextOpenPacketProtectionMaterial()
    {
        retainedNextOpenPacketProtectionMaterial = null;
    }

    internal void ResetRepeatedLocalPacketProtectionUpdateEligibility()
    {
        repeatedLocalPacketProtectionUpdateNotBeforeMicros = null;
        acknowledgedCurrentPacketProtectionKeyPhase = null;
    }

    internal bool TryRecordCurrentPacketProtectionPhaseAcknowledgment(
        ulong keyPhase,
        ulong acknowledgedAtMicros,
        ulong probeTimeoutMicros)
    {
        if (acknowledgedCurrentPacketProtectionKeyPhase.HasValue)
        {
            return false;
        }

        acknowledgedCurrentPacketProtectionKeyPhase = keyPhase;
        ulong cooldownMicros = MultiplySaturating(Math.Max(probeTimeoutMicros, 1UL), ThreePtoMultiplier);
        repeatedLocalPacketProtectionUpdateNotBeforeMicros = SaturatingAdd(acknowledgedAtMicros, cooldownMicros);
        return true;
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

    internal bool TryArmRetainedOldPacketProtectionMaterialDiscard(
        ulong discardAtMicros,
        ulong keyPhase)
    {
        if (!HasRetainedOldPacketProtectionMaterial
            || HasRetainedOldPacketProtectionDiscardDeadline)
        {
            return false;
        }

        retainedOldPacketProtectionDiscardAtMicros = discardAtMicros;
        retainedOldPacketProtectionKeyPhase = keyPhase;
        return true;
    }

    internal bool TryDiscardRetainedOldPacketProtectionMaterial()
    {
        if (!HasRetainedOldPacketProtectionMaterial)
        {
            return false;
        }

        retainedOldOpenPacketProtectionMaterial = null;
        retainedOldProtectPacketProtectionMaterial = null;
        retainedOldPacketProtectionDiscardAtMicros = null;
        retainedOldPacketProtectionKeyPhase = null;
        return true;
    }

    internal void Reset()
    {
        retainedOldOpenPacketProtectionMaterial = null;
        retainedOldProtectPacketProtectionMaterial = null;
        retainedNextOpenPacketProtectionMaterial = null;
        retainedOldPacketProtectionDiscardAtMicros = null;
        retainedOldPacketProtectionKeyPhase = null;
        repeatedLocalPacketProtectionUpdateNotBeforeMicros = null;
        acknowledgedCurrentPacketProtectionKeyPhase = null;
    }

    private static ulong MultiplySaturating(ulong value, ulong multiplier)
    {
        if (value == 0 || multiplier == 0)
        {
            return 0;
        }

        ulong product = value * multiplier;
        return product / multiplier != value ? ulong.MaxValue : product;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }
}
