namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0021">An endpoint that receives packets it cannot process MUST send a packet using the Stateless Reset layout shown in Figure 10.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0021")]
public sealed class REQ_QUIC_RFC9000_S10P3_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_UsesTheFigure10LayoutForUnprocessablePackets()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x30);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(datagram, token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStatelessResetDatagram_RejectsPacketsWithoutRoomForTheLayout()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x30);
        Span<byte> destination = stackalloc byte[QuicStatelessReset.MinimumDatagramLength - 1];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, QuicStatelessReset.MinimumDatagramLength, destination, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatStatelessResetDatagram_UsesTheMinimumFigure10Layout()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x30);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(datagram, token);
    }
}
