namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0356")]
public sealed class REQ_QUIC_RFC9000_0356
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerMayTreatUpdatedHandshakeTransportParameterUseInZeroRttAsProtocolViolation()
    {
        QuicTransportErrorCode? errorCode =
            QuicZeroRttTransportParameterPolicy.GetServerZeroRttTransportParameterUseError(
                QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake);

        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerMayTreatUpdatedOneRttFrameTransportParameterUseInZeroRttAsProtocolViolation()
    {
        QuicTransportErrorCode? errorCode =
            QuicZeroRttTransportParameterPolicy.GetServerZeroRttTransportParameterUseError(
                QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame);

        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerDoesNotTreatRememberedTransportParameterUseInZeroRttAsProtocolViolation()
    {
        QuicTransportErrorCode? errorCode =
            QuicZeroRttTransportParameterPolicy.GetServerZeroRttTransportParameterUseError(
                QuicZeroRttTransportParameterValueSource.Remembered);

        Assert.Null(errorCode);
    }
}
