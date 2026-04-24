namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0007">When the stateless-reset helper cannot format a response because the token length, datagram length, destination space, or version-profile snapshot is invalid, it MUST fail the formatting attempt and callers MUST suppress emission rather than inventing a stateless-reset datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0007")]
public sealed class REQ_QUIC_RFC9001_S6P6_0007
{
    public static TheoryData<int, int> UndersizedFormatCases => new()
    {
        { QuicStatelessReset.MinimumDatagramLength - 1, QuicStatelessReset.MinimumDatagramLength },
        { QuicStatelessReset.MinimumDatagramLength, QuicStatelessReset.MinimumDatagramLength - 1 },
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatStatelessResetDatagram_WritesTheMinimumLengthDatagramAndKeepsTheTokenAtTheTail()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x77);
        byte[] datagram = new byte[QuicStatelessReset.MinimumDatagramLength];

        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(token, datagram.Length, datagram, out int bytesWritten));
        Assert.Equal(datagram.Length, bytesWritten);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(datagram, token);
    }

    [Theory]
    [MemberData(nameof(UndersizedFormatCases))]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatStatelessResetDatagram_RejectsUndersizedDestinationOrDatagramLength(
        int destinationLength,
        int datagramLength)
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x78);
        byte[] destination = new byte[destinationLength];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, datagramLength, destination, out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatStatelessResetDatagram_RejectsEmptyVersionProfileSnapshots()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x79);
        byte[] destination = new byte[QuicStatelessReset.MinimumDatagramLength];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(
            token,
            ReadOnlySpan<uint>.Empty,
            destination.Length,
            destination,
            out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }
}
