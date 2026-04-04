namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP3-0001">At the beginning of a connection, the congestion control state MUST be initialized by setting congestion_window to kInitialWindow, bytes_in_flight to 0, congestion_recovery_start_time to 0, ssthresh to infinite, and each ECN-CE counter to 0.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP3-0001")]
public sealed class REQ_QUIC_RFC9002_SBP3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Constructor_InitializesTheCongestionControlStateAtConnectionStart()
    {
        QuicCongestionControlState state = new();
        ulong[] ecnCeCounters = GetEcnCeCounters(state);

        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Null(state.RecoveryStartTimeMicros);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.Equal([0UL, 0UL, 0UL], ecnCeCounters);
    }

    private static ulong[] GetEcnCeCounters(QuicCongestionControlState state)
    {
        System.Reflection.FieldInfo field = typeof(QuicCongestionControlState).GetField(
            "ecnCeCounters",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Missing ecnCeCounters field.");

        return Assert.IsType<ulong[]>(field.GetValue(state));
    }
}
