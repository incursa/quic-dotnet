using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0003">Each stream MUST be identified within a connection by a numeric value called the stream ID.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
public sealed class REQ_QUIC_RFC9000_S2P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamIdentifier_ReportsTheEncodedStreamIdValue()
    {
        ulong value = 6;
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
        Assert.Equal(value, streamId.Value);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Property(Arbitrary = new[] { typeof(QuicVariableLengthIntegerPropertyGenerators) })]
    [Trait("Category", "Property")]
    public void TryParseStreamIdentifier_RoundTripsRepresentableValues(ulong value)
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
        Assert.Equal(value, streamId.Value);
        Assert.Equal(bytesConsumed, encoded.Length);
        Assert.Equal((value & 0x02) == 0 ? QuicStreamType.Bidirectional : QuicStreamType.Unidirectional, streamId.StreamType);
        Assert.Equal((value & 0x01) == 0, streamId.IsClientInitiated);
        Assert.Equal((value & 0x01) != 0, streamId.IsServerInitiated);
        Assert.Equal((value & 0x02) == 0, streamId.IsBidirectional);
        Assert.Equal((value & 0x02) != 0, streamId.IsUnidirectional);
    }
}
