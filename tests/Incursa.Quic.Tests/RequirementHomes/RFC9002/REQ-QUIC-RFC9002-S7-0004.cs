namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0004">QUIC MAY use loss of ACK-only packets to adjust the congestion controller or the rate of ACK-only packets being sent.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7-0004")]
public sealed class REQ_QUIC_RFC9002_S7_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterLoss_AllowsAckOnlyLossSignalsToEnterRecovery()
    {
        QuicCongestionControlState state = new();
        ulong initialCongestionWindowBytes = state.CongestionWindowBytes;

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 4_000,
            packetInFlight: false,
            allowAckOnlyLossSignal: true));

        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(4_000UL, state.RecoveryStartTimeMicros!.Value);
        Assert.True(state.CongestionWindowBytes < initialCongestionWindowBytes);
        Assert.Equal(state.CongestionWindowBytes, state.SlowStartThresholdBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryRegisterLoss_IgnoresNonInflightPacketsWhenAckOnlyLossSignalsAreDisabled()
    {
        QuicCongestionControlState state = new();
        ulong initialCongestionWindowBytes = state.CongestionWindowBytes;

        Assert.False(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 4_000,
            packetInFlight: false,
            allowAckOnlyLossSignal: false));

        Assert.False(state.HasRecoveryStartTime);
        Assert.Null(state.RecoveryStartTimeMicros);
        Assert.Equal(initialCongestionWindowBytes, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryRegisterLoss_AckOnlyLossSignalsDoNotRemoveBytesFromFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(2_400);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 4_000,
            packetInFlight: false,
            allowAckOnlyLossSignal: true));

        Assert.Equal(2_400UL, state.BytesInFlightBytes);
        Assert.True(state.HasRecoveryStartTime);
    }
}
