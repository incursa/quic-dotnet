namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0001">On-path observers MAY measure the time between two spin bit toggle events to estimate the end-to-end RTT of a connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P4-0001")]
public sealed class REQ_QUIC_RFC9000_S17P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryMeasureSpinBitToggleInterval_ObservesElapsedTicksBetweenTwoToggleEvents()
    {
        SpinBitObservation[] observations =
        [
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x00, []), 100L),
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x20, []), 250L),
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x00, []), 400L),
        ];

        Assert.True(TryMeasureSpinBitToggleInterval(observations, out long elapsedTicks));
        Assert.Equal(150L, elapsedTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryMeasureSpinBitToggleInterval_RejectsSequencesWithoutTwoToggleEvents()
    {
        SpinBitObservation[] observations =
        [
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x00, []), 100L),
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x00, []), 250L),
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x20, []), 400L),
        ];

        Assert.False(TryMeasureSpinBitToggleInterval(observations, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryMeasureSpinBitToggleInterval_HandlesTheShortestValid1RttPackets()
    {
        SpinBitObservation[] observations =
        [
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x20, []), 1L),
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x00, []), 2L),
            new SpinBitObservation(QuicHeaderTestData.BuildShortHeader(0x20, []), 3L),
        ];

        Assert.True(TryMeasureSpinBitToggleInterval(observations, out long elapsedTicks));
        Assert.Equal(1L, elapsedTicks);
    }

    private static bool TryMeasureSpinBitToggleInterval(
        SpinBitObservation[] observations,
        out long elapsedTicks)
    {
        elapsedTicks = default;
        if (observations.Length < 3)
        {
            return false;
        }

        if (!QuicPacketParser.TryParseShortHeader(observations[0].Packet, out QuicShortHeaderPacket firstHeader)
            || !QuicPacketParser.TryParseShortHeader(observations[1].Packet, out QuicShortHeaderPacket secondHeader)
            || !QuicPacketParser.TryParseShortHeader(observations[2].Packet, out QuicShortHeaderPacket thirdHeader))
        {
            return false;
        }

        if (firstHeader.SpinBit == secondHeader.SpinBit
            || secondHeader.SpinBit == thirdHeader.SpinBit)
        {
            return false;
        }

        elapsedTicks = observations[2].ObservedAtTicks - observations[1].ObservedAtTicks;
        return true;
    }

    private readonly record struct SpinBitObservation(byte[] Packet, long ObservedAtTicks);
}
