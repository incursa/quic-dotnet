namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0011">Violations of the protocol MUST lead to an immediate close.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2-0011")]
public sealed class REQ_QUIC_RFC9000_S10P2_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S10P2-0011")]
    public void PacketNumberExhaustion_ClosesTheConnectionImmediatelyOnProtocolViolation()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        runtime.HandshakeFlowCoordinator.SetNextApplicationPacketNumberForTests(QuicVariableLengthInteger.MaxValue);

        List<QuicConnectionEffect>? effects = [];
        Assert.True(runtime.TrySendRecoveryPingProbe(ref effects));
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Contains(effects!, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(effects!, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S10P2-0011")]
    public void RecoveryProbeBeforePacketNumberExhaustionDoesNotDiscardTheConnection()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        List<QuicConnectionEffect>? effects = [];
        Assert.True(runtime.TrySendRecoveryPingProbe(ref effects));
        Assert.NotEqual(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.DoesNotContain(effects!, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

}
