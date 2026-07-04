// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S10-2-P3-S1-R01">Violations of the protocol MUST lead to an immediate close.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-2-P3-S1-R01")]
public sealed class RFC9000_S10_2_P3_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("RFC9000-S10-2-P3-S1-R01")]
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
    [Requirement("RFC9000-S10-2-P3-S1-R01")]
    public void RecoveryProbeBeforePacketNumberExhaustionDoesNotDiscardTheConnection()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        List<QuicConnectionEffect>? effects = [];
        Assert.True(runtime.TrySendRecoveryPingProbe(ref effects));
        Assert.NotEqual(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.DoesNotContain(effects!, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

}
