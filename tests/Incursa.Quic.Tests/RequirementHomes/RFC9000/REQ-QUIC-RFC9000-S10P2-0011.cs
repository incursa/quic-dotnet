using System.Reflection;

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

        QuicHandshakeFlowCoordinator coordinator = GetPrivateField<QuicHandshakeFlowCoordinator>(runtime, "handshakeFlowCoordinator");
        SetPrivateField(coordinator, "nextApplicationPacketNumber", QuicVariableLengthInteger.MaxValue);

        List<QuicConnectionEffect>? effects = [];
        Assert.True(InvokeTrySendRecoveryPingProbe(runtime, ref effects));
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
        Assert.True(InvokeTrySendRecoveryPingProbe(runtime, ref effects));
        Assert.NotEqual(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.DoesNotContain(effects!, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    private static bool InvokeTrySendRecoveryPingProbe(
        QuicConnectionRuntime runtime,
        ref List<QuicConnectionEffect>? effects)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TrySendRecoveryPingProbe",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

        object?[] arguments =
        [
            effects,
        ];

        bool result = (bool)method.Invoke(runtime, arguments)!;
        effects = (List<QuicConnectionEffect>?)arguments[0];
        return result;
    }

    private static T GetPrivateField<T>(
        object target,
        string fieldName)
    {
        FieldInfo field = target.GetType().GetField(
            fieldName,
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        return (T)field.GetValue(target)!;
    }

    private static void SetPrivateField<T>(
        object target,
        string fieldName,
        T value)
    {
        FieldInfo field = target.GetType().GetField(
            fieldName,
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        field.SetValue(target, value);
    }
}
