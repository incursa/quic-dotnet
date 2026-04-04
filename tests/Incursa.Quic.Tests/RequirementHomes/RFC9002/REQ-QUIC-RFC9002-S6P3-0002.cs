namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P3-0002")]
public sealed class REQ_QUIC_RFC9002_S6P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetProbeTimeoutBackoffCount_ResetsTheBackoffWhenRetryDiscardsKeys()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 3,
            initialOrHandshakeKeysDiscarded: true));
    }
}
