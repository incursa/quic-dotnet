namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0009">To achieve that end, the endpoint SHOULD ensure that all packets it sends are at least 22 bytes longer than the minimum connection ID length that it requests the peer to include in its packets, adding PADDING frames as necessary.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0009")]
public sealed class REQ_QUIC_RFC9000_S10P3_0009
{
    [Theory]
    [InlineData(0, 22)]
    [InlineData(8, 30)]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetMinimumPacketLengthForResetResistance_OffsetsByTwentyTwoBytes(
        int minimumConnectionIdLength,
        int expectedLength)
    {
        Assert.True(QuicStatelessReset.TryGetMinimumPacketLengthForResetResistance(minimumConnectionIdLength, out int minimumPacketLength));
        Assert.Equal(expectedLength, minimumPacketLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryGetMinimumPacketLengthForResetResistance_HandlesTheLargestSafeInput()
    {
        int minimumConnectionIdLength = int.MaxValue - 22;

        Assert.True(QuicStatelessReset.TryGetMinimumPacketLengthForResetResistance(minimumConnectionIdLength, out int minimumPacketLength));
        Assert.Equal(int.MaxValue, minimumPacketLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGetMinimumPacketLengthForResetResistance_RejectsNegativeOrOverflowingInputs()
    {
        Assert.False(QuicStatelessReset.TryGetMinimumPacketLengthForResetResistance(-1, out _));
        Assert.False(QuicStatelessReset.TryGetMinimumPacketLengthForResetResistance(int.MaxValue - 21, out _));
    }
}
