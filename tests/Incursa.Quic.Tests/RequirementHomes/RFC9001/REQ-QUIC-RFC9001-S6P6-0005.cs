namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0005">If a key update is not possible or integrity limits are reached, an endpoint MUST send only stateless resets in response to received packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0005")]
public sealed class REQ_QUIC_RFC9001_S6P6_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyAllowsOnlyStatelessResetsAfterConnectionStoppedForAeadLimit()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 16, integrityLimit: 16);

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: true);

        Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
        Assert.True(decision.RequiresConnectionStop);
        Assert.True(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyAllowsOnlyStatelessResetsAfterIntegrityLimitIsReached()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 16, integrityLimit: 1);

        Assert.True(keyLifecycle.TryUseForOpening());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: false);

        Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
        Assert.True(decision.RequiresConnectionStop);
        Assert.True(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadLimitPolicyKeepsOrdinaryResponsesBeforeAeadStop()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 4, integrityLimit: 4);

        Assert.True(keyLifecycle.TryUseForOpening());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: false);

        Assert.Equal(QuicAeadLimitAction.Continue, decision.Action);
        Assert.Null(decision.TransportErrorCode);
        Assert.False(decision.RequiresConnectionStop);
        Assert.False(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzStatelessResetOnlyPolicy_RandomizedIntegrityLimitsChooseStatelessResetOnly()
    {
        Random random = new(unchecked((int)0x9001_6605));

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int integrityLimit = random.Next(1, 24);
            QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 128, integrityLimit);

            for (int packet = 0; packet < integrityLimit; packet++)
            {
                Assert.True(keyLifecycle.TryUseForOpening());
            }

            QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
                keyLifecycle,
                connectionStoppedForAeadLimit: false);

            Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
            Assert.True(decision.AllowsOnlyStatelessReset);
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
