namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0247")]
public sealed class REQ_QUIC_RFC9000_0247
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NewConnectionIdFrame_WithinRetirementCapacityDoesNotCloseTheConnection()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.True(QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionId: [0x70, 0x71, 0x72],
            observedAtTicks: 9,
            statelessResetTokenStart: 0x70).StateChanged);

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 2UL,
            retirePriorTo: 1UL,
            connectionId: [0x80, 0x81, 0x82],
            observedAtTicks: 10,
            statelessResetTokenStart: 0x80);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.NotEqual(
            QuicTransportErrorCode.ConnectionIdLimitError,
            runtime.TerminalState?.Close.TransportErrorCode);
    }
}
