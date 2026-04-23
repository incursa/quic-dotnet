namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0001">Endpoints MUST count the number of encrypted packets for each set of packet protection keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0001")]
public sealed class REQ_QUIC_RFC9001_S6P6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadKeyLifecycleCountsProtectedPacketsForOneKeySet()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 4, integrityLimit: 16);

        Assert.True(keyLifecycle.TryUseForProtection());
        Assert.True(keyLifecycle.TryUseForProtection());
        Assert.True(keyLifecycle.TryUseForProtection());

        Assert.Equal(3d, keyLifecycle.ProtectedPacketCount);
        Assert.Equal(0d, keyLifecycle.OpenedPacketCount);
        Assert.True(keyLifecycle.CanProtect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadKeyLifecycleKeepsProtectedPacketCountsSeparatePerKeySet()
    {
        QuicAeadKeyLifecycle firstKeySet = CreateActiveLifecycle(confidentialityLimit: 4, integrityLimit: 16);
        QuicAeadKeyLifecycle secondKeySet = CreateActiveLifecycle(confidentialityLimit: 4, integrityLimit: 16);

        Assert.True(firstKeySet.TryUseForProtection());
        Assert.True(firstKeySet.TryUseForProtection());
        Assert.True(secondKeySet.TryUseForProtection());

        Assert.Equal(2d, firstKeySet.ProtectedPacketCount);
        Assert.Equal(1d, secondKeySet.ProtectedPacketCount);
        Assert.True(firstKeySet.CanProtect);
        Assert.True(secondKeySet.CanProtect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadKeyLifecycleDoesNotCountProtectionAttemptsBeforeKeysAreAvailable()
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(4, 16));

        Assert.False(keyLifecycle.TryUseForProtection());
        Assert.False(keyLifecycle.CanProtect);
        Assert.Equal(0d, keyLifecycle.ProtectedPacketCount);
        Assert.Equal(0d, keyLifecycle.OpenedPacketCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzProtectedPacketCounting_RandomizedLimitsKeepCountsPerKeySet()
    {
        Random random = new(unchecked((int)0x9001_6601));

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int firstUses = random.Next(0, 8);
            int secondUses = random.Next(0, 8);
            int confidentialityLimit = random.Next(8, 16);
            QuicAeadKeyLifecycle firstKeySet = CreateActiveLifecycle(confidentialityLimit, integrityLimit: 32);
            QuicAeadKeyLifecycle secondKeySet = CreateActiveLifecycle(confidentialityLimit, integrityLimit: 32);

            UseForProtection(firstKeySet, firstUses);
            UseForProtection(secondKeySet, secondUses);

            Assert.Equal((double)firstUses, firstKeySet.ProtectedPacketCount);
            Assert.Equal((double)secondUses, secondKeySet.ProtectedPacketCount);
            Assert.True(firstKeySet.CanProtect);
            Assert.True(secondKeySet.CanProtect);
        }
    }

    private static QuicAeadKeyLifecycle CreateActiveLifecycle(int confidentialityLimit, int integrityLimit)
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(confidentialityLimit, integrityLimit));
        Assert.True(keyLifecycle.TryActivate());
        return keyLifecycle;
    }

    private static void UseForProtection(QuicAeadKeyLifecycle keyLifecycle, int packetCount)
    {
        for (int i = 0; i < packetCount; i++)
        {
            Assert.True(keyLifecycle.TryUseForProtection());
        }
    }
}
