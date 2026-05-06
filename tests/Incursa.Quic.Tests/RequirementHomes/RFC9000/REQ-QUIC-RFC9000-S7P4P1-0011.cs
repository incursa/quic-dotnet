namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4P1-0011")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttPacketUsesRememberedTransportParametersOnly()
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.ZeroRtt,
                QuicZeroRttTransportParameterValueSource.Remembered);

        Assert.True(decision.CanUse);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroRttPacketRejectsNonRememberedTransportParameterSource()
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.ZeroRtt,
                QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake);

        Assert.False(decision.CanUse);
        Assert.Equal(QuicZeroRttTransportParameterUseFailure.UpdatedHandshakeValueInZeroRtt, decision.Failure);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ZeroRttPacketRejectsUnknownTransportParameterSource()
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.ZeroRtt,
                QuicZeroRttTransportParameterValueSource.Unknown);

        Assert.False(decision.CanUse);
        Assert.Equal(QuicZeroRttTransportParameterUseFailure.MissingRememberedValue, decision.Failure);
        Assert.Null(decision.ErrorCode);
    }
}
