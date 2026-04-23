namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P3-0002")]
public sealed class REQ_QUIC_RFC9000_S14P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryTrackPaddingProbe_ComputesPaddingDataForTheTargetProbeSize()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.11", "192.0.2.10", 443, 55555);

        Assert.True(state.TryTrackPaddingProbe(
            path,
            packetNumber: 20,
            probeSizeBytes: 1_300,
            ackElicitingPayloadSizeBytes: 37,
            out ulong paddingFrameBytes));

        Assert.Equal(1_263UL, paddingFrameBytes);
        Assert.Equal(1, state.GetPathSnapshot(path).OutstandingProbeCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryTrackPaddingProbe_RejectsPurePaddingWithoutAckElicitingPayload()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.11", "192.0.2.10", 443, 55555);

        Assert.False(state.TryTrackPaddingProbe(
            path,
            packetNumber: 20,
            probeSizeBytes: 1_300,
            ackElicitingPayloadSizeBytes: 0,
            out ulong paddingFrameBytes));

        Assert.Equal(0UL, paddingFrameBytes);
        Assert.Equal(0, state.GetPathSnapshot(path).OutstandingProbeCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryTrackPaddingProbe_RejectsTargetsThatLeaveNoPaddingData()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.11", "192.0.2.10", 443, 55555);

        Assert.False(state.TryTrackPaddingProbe(
            path,
            packetNumber: 20,
            probeSizeBytes: 1_300,
            ackElicitingPayloadSizeBytes: 1_300,
            out ulong paddingFrameBytes));

        Assert.Equal(0UL, paddingFrameBytes);
        Assert.Equal(0, state.GetPathSnapshot(path).OutstandingProbeCount);
    }
}
