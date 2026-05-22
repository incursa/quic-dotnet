namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18-0003")]
public sealed class REQ_QUIC_RFC9000_S18_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-1103")]
    public void TryFormatTransportParameters_EmitsTheExpectedTupleSequence()
    {
        byte[] maxIdleTimeoutValue = QuicVarintTestData.EncodeMinimal(25);
        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, maxIdleTimeoutValue),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0C, []));

        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 25,
            DisableActiveMigration = true,
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        byte[] expectedId = QuicVarintTestData.EncodeMinimal(0x01);
        byte[] expectedLength = QuicVarintTestData.EncodeMinimal((ulong)maxIdleTimeoutValue.Length);
        Assert.True(expectedId.AsSpan().SequenceEqual(destination[..expectedId.Length]));
        Assert.True(expectedLength.AsSpan().SequenceEqual(destination[expectedId.Length..(expectedId.Length + expectedLength.Length)]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.Equal(25UL, parsed.MaxIdleTimeout);
        Assert.True(parsed.DisableActiveMigration);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-1103")]
    public void TryParseTransportParameters_AcceptsTwoByteVarintTupleBoundaries()
    {
        byte[] value = new byte[64];
        for (int index = 0; index < value.Length; index++)
        {
            value[index] = (byte)index;
        }

        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(64, value);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        byte[] expectedId = QuicVarintTestData.EncodeMinimal(64);
        byte[] expectedLength = QuicVarintTestData.EncodeMinimal((ulong)value.Length);
        Assert.True(expectedId.AsSpan().SequenceEqual(encoded[..expectedId.Length]));
        Assert.True(expectedLength.AsSpan().SequenceEqual(encoded[expectedId.Length..(expectedId.Length + expectedLength.Length)]));

        Assert.Null(parsed.MaxIdleTimeout);
        Assert.Null(parsed.MaxUdpPayloadSize);
        Assert.False(parsed.DisableActiveMigration);
        Assert.Null(parsed.PreferredAddress);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0003">Each transport parameter MUST be encoded as an (identifier, length, value) tuple, as shown in Figure 21:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0004">The Transport Parameter ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0005">The Transport Parameter Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1103">The Transport Parameter Length field MUST contain the length of the Transport Parameter Value field in bytes.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-1103")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsTruncatedTupleValue()
    {
        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25));
        byte[] truncated = tuple[..^1];

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            truncated,
            QuicTransportParameterRole.Client,
            out _));
    }
}
