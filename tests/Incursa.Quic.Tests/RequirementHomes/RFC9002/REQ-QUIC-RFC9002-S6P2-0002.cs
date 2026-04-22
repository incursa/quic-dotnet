namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2-0002">The PTO MUST be computed separately for each packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2-0002")]
public sealed class REQ_QUIC_RFC9002_S6P2_0002
{
    public static TheoryData<object> ZeroAckDelayCases => new()
    {
        new ProbeTimeoutSpaceCase(QuicPacketNumberSpace.Initial, false, 2_000),
        new ProbeTimeoutSpaceCase(QuicPacketNumberSpace.ApplicationData, true, 2_000),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeProbeTimeoutMicros_RejectsApplicationDataBeforeHandshakeConfirmation()
    {
        Assert.False(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: 200,
            maxAckDelayMicros: 500,
            handshakeConfirmed: false,
            out _));
    }

    [Theory]
    [MemberData(nameof(ZeroAckDelayCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeProbeTimeoutMicros_UsesTheSameBaseTimeoutAtTheAckDelayBoundary(object scenarioValue)
    {
        ProbeTimeoutSpaceCase scenario = (ProbeTimeoutSpaceCase)scenarioValue;

        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            scenario.PacketNumberSpace,
            smoothedRttMicros: 1_000,
            rttVarMicros: 200,
            maxAckDelayMicros: 0,
            handshakeConfirmed: scenario.HandshakeConfirmed,
            out ulong probeTimeoutMicros));

        Assert.Equal(scenario.ExpectedProbeTimeoutMicros, probeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectPtoTimeAndSpace_UsesTheCurrentPathRttForHandshakeAfterAnInitialAck()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-092456744-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-092456744-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-092456744-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\sim\trace_node_left.pcap
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-092456744-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\sim\trace_node_right.pcap
        // In preserved connection 37/50 the client received prompt peer progress on the path, but the
        // next client Handshake repair still waited roughly three seconds. Regress that bounded failure:
        // an Initial-space RTT sample must immediately tighten the later Handshake PTO on the same path.
        QuicRecoveryController controller = new();

        controller.RecordPacketSent(QuicPacketNumberSpace.Initial, packetNumber: 1, sentAtMicros: 100_000);
        controller.RecordPacketSent(QuicPacketNumberSpace.Handshake, packetNumber: 2, sentAtMicros: 100_000);

        Assert.True(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.Initial,
            largestAcknowledgedPacketNumber: 1,
            ackReceivedAtMicros: 140_000,
            newlyAcknowledgedAckElicitingPacketNumbers: new ulong[] { 1 },
            isInitialPacket: true,
            ignoreAckDelayForInitialPacket: true));

        Assert.True(controller.TrySelectPtoTimeAndSpace(
            nowMicros: 140_000,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false,
            handshakeKeysAvailable: true,
            out ulong selectedProbeTimeoutMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(QuicPacketNumberSpace.Handshake, selectedPacketNumberSpace);
        Assert.Equal(260_000UL, selectedProbeTimeoutMicros);
    }

    internal sealed record ProbeTimeoutSpaceCase(
        QuicPacketNumberSpace PacketNumberSpace,
        bool HandshakeConfirmed,
        ulong ExpectedProbeTimeoutMicros);
}
