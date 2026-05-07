namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0004">A stream ID MUST be a 62-bit integer in the range 0 to 2^62-1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P1-0004")]
public sealed class REQ_QUIC_RFC9000_S2P1_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamIdentifier_AcceptsTheMaximumRepresentableStreamId()
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(QuicVariableLengthInteger.MaxValue);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, streamId.Value);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BuildStreamIdentifier_RejectsValuesBeyondThe62BitRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicStreamTestData.BuildStreamIdentifier(QuicVariableLengthInteger.MaxValue + 1UL));
    }
}
