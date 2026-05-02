using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0010">If the packet number for sending reaches 2^62-1, the sender MUST close the connection without sending a CONNECTION_CLOSE frame or any further packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0010")]
public sealed class REQ_QUIC_RFC9000_S12P3_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedHandshakePacket_AllowsTheLastSendablePacketNumberBeforeExhaustion()
    {
        QuicHandshakeFlowCoordinator coordinator = new(
            new byte[] { 0x11, 0x12, 0x13, 0x14 },
            new byte[] { 0x21, 0x22, 0x23, 0x24 });

        SetPrivateField(coordinator, "nextPacketNumber", QuicVariableLengthInteger.MaxValue - 1);

        QuicTlsPacketProtectionMaterial material = QuicS13AckPiggybackTestSupport.CreateHandshakeMaterial();
        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x40, 24);

        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            material,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, packetNumber);
        Assert.NotEmpty(protectedPacket);
        Assert.Equal(
            QuicVariableLengthInteger.MaxValue,
            GetPrivateField<ulong>(coordinator, "nextPacketNumber"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedApplicationDataPacket_ReturnsFalseWhenThePacketNumberSpaceIsExhausted()
    {
        QuicHandshakeFlowCoordinator coordinator = new(new byte[] { 0x31, 0x32, 0x33, 0x34 });
        SetPrivateField(coordinator, "nextApplicationPacketNumber", QuicVariableLengthInteger.MaxValue);

        QuicTlsPacketProtectionMaterial material = QuicS9P3TokenEmissionTestSupport.CreateOneRttMaterial();

        Assert.False(coordinator.TryBuildProtectedApplicationDataPacket(
            new byte[] { 0x01, 0x02, 0x03 },
            material,
            keyPhase: false,
            out _,
            out _));
        Assert.Equal(
            QuicVariableLengthInteger.MaxValue,
            GetPrivateField<ulong>(coordinator, "nextApplicationPacketNumber"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySendRecoveryPingProbe_DiscardsTheConnectionWhenApplicationPacketNumbersAreExhausted()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicHandshakeFlowCoordinator coordinator = GetPrivateField<QuicHandshakeFlowCoordinator>(runtime, "handshakeFlowCoordinator");
        SetPrivateField(coordinator, "nextApplicationPacketNumber", QuicVariableLengthInteger.MaxValue);

        List<QuicConnectionEffect>? effects = [];
        Assert.True(InvokeTrySendRecoveryPingProbe(runtime, ref effects));

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Contains(effects!, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(effects!, effect => effect is QuicConnectionSendDatagramEffect);
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
