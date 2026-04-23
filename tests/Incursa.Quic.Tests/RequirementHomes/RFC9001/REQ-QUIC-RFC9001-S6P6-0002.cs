namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0002">If encrypted packet count with the same key exceeds the AEAD confidentiality limit, the endpoint MUST stop using that key.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0002")]
public sealed class REQ_QUIC_RFC9001_S6P6_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadKeyLifecycleDiscardsProtectionKeysWhenConfidentialityLimitIsReached()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 2, integrityLimit: 16);

        Assert.True(keyLifecycle.TryUseForProtection());
        Assert.True(keyLifecycle.CanProtect);

        Assert.True(keyLifecycle.TryUseForProtection());

        Assert.Equal(2d, keyLifecycle.ProtectedPacketCount);
        Assert.True(keyLifecycle.IsDiscarded);
        Assert.False(keyLifecycle.CanProtect);
        Assert.False(keyLifecycle.CanOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadKeyLifecycleRejectsProtectionBeyondTheConfidentialityLimitWithoutIncreasingTheCount()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 1, integrityLimit: 16);

        Assert.True(keyLifecycle.TryUseForProtection());
        Assert.False(keyLifecycle.TryUseForProtection());

        Assert.Equal(1d, keyLifecycle.ProtectedPacketCount);
        Assert.True(keyLifecycle.IsDiscarded);
        Assert.False(keyLifecycle.CanProtect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadKeyLifecycleKeepsIndependentKeySetsAvailableWhenAnotherKeySetReachesItsLimit()
    {
        QuicAeadKeyLifecycle exhaustedKeySet = CreateActiveLifecycle(confidentialityLimit: 1, integrityLimit: 16);
        QuicAeadKeyLifecycle freshKeySet = CreateActiveLifecycle(confidentialityLimit: 2, integrityLimit: 16);

        Assert.True(exhaustedKeySet.TryUseForProtection());

        Assert.True(exhaustedKeySet.IsDiscarded);
        Assert.False(exhaustedKeySet.CanProtect);
        Assert.True(freshKeySet.CanProtect);
        Assert.True(freshKeySet.TryUseForProtection());
        Assert.Equal(1d, freshKeySet.ProtectedPacketCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzConfidentialityLimitExhaustion_RandomizedLimitsRejectTheFirstExcessProtectionAttempt()
    {
        Random random = new(unchecked((int)0x9001_6602));

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int confidentialityLimit = random.Next(1, 12);
            QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit, integrityLimit: 64);

            for (int packet = 0; packet < confidentialityLimit; packet++)
            {
                Assert.True(keyLifecycle.TryUseForProtection());
            }

            Assert.Equal((double)confidentialityLimit, keyLifecycle.ProtectedPacketCount);
            Assert.True(keyLifecycle.IsDiscarded);
            Assert.False(keyLifecycle.CanProtect);
            Assert.False(keyLifecycle.TryUseForProtection());
            Assert.Equal((double)confidentialityLimit, keyLifecycle.ProtectedPacketCount);
        }
    }

    private static QuicAeadKeyLifecycle CreateActiveLifecycle(int confidentialityLimit, int integrityLimit)
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(confidentialityLimit, integrityLimit));
        Assert.True(keyLifecycle.TryActivate());
        return keyLifecycle;
    }
}
