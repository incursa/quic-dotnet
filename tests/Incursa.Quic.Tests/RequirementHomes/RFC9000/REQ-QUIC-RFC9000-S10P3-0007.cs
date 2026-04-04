namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0007">The remainder of the first byte and an arbitrary number of bytes following it are set to values that SHOULD be indistinguishable from random.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0007")]
public sealed class REQ_QUIC_RFC9000_S10P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_FillsTheLeadingBytesWithRandomizedContent()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();

        byte[] firstDatagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength + 8);
        byte[] secondDatagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength + 8);

        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(firstDatagram);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(secondDatagram);
        Assert.False(firstDatagram.AsSpan().SequenceEqual(secondDatagram));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatStatelessResetDatagram_StillUsesRandomizedContentAtTheMinimumLength()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStatelessResetDatagram_RejectsDatagramsWithoutRoomForRandomizedContent()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        Span<byte> destination = stackalloc byte[QuicStatelessReset.MinimumDatagramLength - 1];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, QuicStatelessReset.MinimumDatagramLength - 1, destination, out _));
    }
}
