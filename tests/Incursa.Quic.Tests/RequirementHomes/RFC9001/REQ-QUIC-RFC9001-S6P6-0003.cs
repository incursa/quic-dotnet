namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0003">Endpoints MUST initiate a key update before sending more protected packets than the selected AEAD confidentiality limit permits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0003")]
public sealed class REQ_QUIC_RFC9001_S6P6_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyRequestsKeyUpdateWhenConfidentialityLimitBlocksFurtherProtection()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 1, integrityLimit: 16);

        Assert.True(keyLifecycle.TryUseForProtection());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            keyLifecycle,
            keyUpdatePossible: true);

        Assert.Equal(QuicAeadLimitAction.InitiateKeyUpdate, decision.Action);
        Assert.Null(decision.TransportErrorCode);
        Assert.False(decision.RequiresConnectionStop);
        Assert.False(keyLifecycle.TryUseForProtection());
        Assert.Equal(1d, keyLifecycle.ProtectedPacketCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadLimitPolicyContinuesBeforeConfidentialityLimitIsReached()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 2, integrityLimit: 16);

        Assert.True(keyLifecycle.TryUseForProtection());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            keyLifecycle,
            keyUpdatePossible: true);

        Assert.Equal(QuicAeadLimitAction.Continue, decision.Action);
        Assert.Null(decision.TransportErrorCode);
        Assert.False(decision.RequiresConnectionStop);
        Assert.True(keyLifecycle.CanProtect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzConfidentialityLimitPolicy_RandomizedLimitsRequestKeyUpdateBeforeExcessProtection()
    {
        Random random = new(unchecked((int)0x9001_6603));

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int confidentialityLimit = random.Next(1, 24);
            QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit, integrityLimit: 128);

            for (int packet = 0; packet < confidentialityLimit; packet++)
            {
                Assert.True(keyLifecycle.TryUseForProtection());
            }

            QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
                keyLifecycle,
                keyUpdatePossible: true);

            Assert.Equal(QuicAeadLimitAction.InitiateKeyUpdate, decision.Action);
            Assert.Equal((double)confidentialityLimit, keyLifecycle.ProtectedPacketCount);
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
