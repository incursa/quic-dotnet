namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0008")]
public sealed class REQ_QUIC_RFC9000_S20P1_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesGeneralStackFunctionErrorCodes()
    {
        (ulong flowControlWireValue, string flowControlName, string flowControlDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.FlowControlError));
        (ulong streamLimitWireValue, string streamLimitName, string streamLimitDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.StreamLimitError));
        (ulong transportParameterWireValue, string transportParameterName, string transportParameterDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.TransportParameterError));

        Assert.Equal(0x03UL, flowControlWireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.FlowControlError), flowControlName);
        Assert.Equal(flowControlName, ((QuicTransportErrorCode)flowControlWireValue).ToString());
        Assert.NotEmpty(flowControlDescription);

        Assert.Equal(0x04UL, streamLimitWireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.StreamLimitError), streamLimitName);
        Assert.Equal(streamLimitName, ((QuicTransportErrorCode)streamLimitWireValue).ToString());
        Assert.NotEmpty(streamLimitDescription);

        Assert.Equal(0x08UL, transportParameterWireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.TransportParameterError), transportParameterName);
        Assert.Equal(transportParameterName, ((QuicTransportErrorCode)transportParameterWireValue).ToString());
        Assert.NotEmpty(transportParameterDescription);
    }
}
