namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0003")]
public sealed class REQ_QUIC_RFC9000_S20P1_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesInternalError()
    {
        (ulong wireValue, string expectedName, string expectedDescription) = Assert.Single(
            QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes,
            candidate => candidate.ExpectedName == nameof(QuicTransportErrorCode.InternalError));

        Assert.Equal(0x01UL, wireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.InternalError), expectedName);
        Assert.NotEmpty(expectedDescription);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportErrorCodeRegistry_DoesNotMisclassifyInternalErrorAsNoError()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.InternalError,
            triggeringFrameType: 0x02,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out _));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((ulong)QuicTransportErrorCode.InternalError, parsed.ErrorCode);
        Assert.NotEqual((ulong)QuicTransportErrorCode.NoError, parsed.ErrorCode);
    }
}
