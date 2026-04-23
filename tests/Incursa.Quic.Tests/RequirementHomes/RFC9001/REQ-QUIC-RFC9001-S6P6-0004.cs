namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0004">If a key update is not possible or integrity limits are reached, an endpoint MUST stop using the connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0004")]
public sealed class REQ_QUIC_RFC9001_S6P6_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyStopsConnectionWhenConfidentialityLimitIsReachedAndKeyUpdateIsImpossible()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 1, integrityLimit: 16);

        Assert.True(keyLifecycle.TryUseForProtection());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            keyLifecycle,
            keyUpdatePossible: false);

        Assert.Equal(QuicAeadLimitAction.StopUsingConnection, decision.Action);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
        Assert.True(decision.RequiresConnectionStop);
        Assert.False(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyStopsConnectionWhenIntegrityLimitIsReached()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 16, integrityLimit: 1);

        Assert.True(keyLifecycle.TryUseForOpening());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            keyLifecycle,
            keyUpdatePossible: true);

        Assert.Equal(QuicAeadLimitAction.StopUsingConnection, decision.Action);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
        Assert.True(decision.RequiresConnectionStop);
        Assert.True(keyLifecycle.HasReachedIntegrityLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadLimitPolicyDoesNotStopConnectionWhileLimitsRemainAvailable()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 4, integrityLimit: 4);

        Assert.True(keyLifecycle.TryUseForProtection());
        Assert.True(keyLifecycle.TryUseForOpening());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            keyLifecycle,
            keyUpdatePossible: false);

        Assert.Equal(QuicAeadLimitAction.Continue, decision.Action);
        Assert.Null(decision.TransportErrorCode);
        Assert.False(decision.RequiresConnectionStop);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzIntegrityLimitPolicy_RandomizedLimitsStopConnectionAtTheLimit()
    {
        Random random = new(unchecked((int)0x9001_6604));

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int integrityLimit = random.Next(1, 24);
            QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 128, integrityLimit);

            for (int packet = 0; packet < integrityLimit; packet++)
            {
                Assert.True(keyLifecycle.TryUseForOpening());
            }

            QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
                keyLifecycle,
                keyUpdatePossible: true);

            Assert.Equal(QuicAeadLimitAction.StopUsingConnection, decision.Action);
            Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
            Assert.True(decision.RequiresConnectionStop);
            Assert.Equal((double)integrityLimit, keyLifecycle.OpenedPacketCount);
        }
    }

    private static QuicAeadKeyLifecycle CreateActiveLifecycle(int confidentialityLimit, int integrityLimit)
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(confidentialityLimit, integrityLimit));
        Assert.True(keyLifecycle.TryActivate());
        return keyLifecycle;
    }
}
