using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0009">An endpoint MAY send a Stateless Reset in response to further packets that it receives after packet-number exhaustion.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0009")]
public sealed class REQ_QUIC_RFC9000_S12P3_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreateStatelessResetDatagramForPacket_EmitsAfterPacketNumberExhaustionDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.11", RemotePort: 443);
        byte[] routeConnectionId = [0x66, 0x09, 0xA0, 0x09];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xD9);

        ConfigurePacketNumberExhaustionRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            pathIdentity,
            routeConnectionId,
            6909UL,
            token);

        DiscardRuntimeForPacketNumberExhaustion(endpoint, runtime, handle);

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            routeConnectionId,
            triggeringPacketLength: 72);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(pathIdentity, emission.PathIdentity);
        Assert.Equal(triggeringPacket.Length - 1, emission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreateStatelessResetDatagramForPacket_DoesNotEmitBeforePacketNumberExhaustionDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.11", RemotePort: 443);
        byte[] routeConnectionId = [0x66, 0x09, 0xA0, 0x0A];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xDA);

        ConfigurePacketNumberExhaustionRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            pathIdentity,
            routeConnectionId,
            6909UL,
            token);

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            routeConnectionId,
            triggeringPacketLength: 72);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0009")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryCreateStatelessResetDatagramForPacket_EmitsAtTheMinimumStatelessResetLengthAfterPacketNumberExhaustionDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.11", RemotePort: 443);
        byte[] routeConnectionId = [0x66, 0x09, 0xA0, 0x0B];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xDB);

        ConfigurePacketNumberExhaustionRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            pathIdentity,
            routeConnectionId,
            6909UL,
            token);

        DiscardRuntimeForPacketNumberExhaustion(endpoint, runtime, handle);

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            routeConnectionId,
            triggeringPacketLength: QuicStatelessReset.MinimumDatagramLength);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(pathIdentity, emission.PathIdentity);
        Assert.Equal(QuicStatelessReset.MinimumDatagramLength, emission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
    }

    private static void ConfigurePacketNumberExhaustionRetainedRouteEndpoint(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> routeConnectionId,
        ulong resetConnectionId,
        ReadOnlySpan<byte> token)
    {
        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: resetConnectionId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, resetConnectionId, token));
    }

    private static void DiscardRuntimeForPacketNumberExhaustion(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle)
    {
        runtime.HandshakeFlowCoordinator.SetNextApplicationPacketNumberForTests(QuicVariableLengthInteger.MaxValue);

        List<QuicConnectionEffect>? effects = [];
        Assert.True(runtime.TrySendRecoveryPingProbe(ref effects));
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(
            "The connection reached the packet number exhaustion limit.",
            runtime.TerminalState?.Close.ReasonPhrase);
        Assert.Contains(effects!, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(effects!, effect => effect is QuicConnectionSendDatagramEffect);

        QuicConnectionDiscardConnectionStateEffect? discardEffect = null;
        foreach (QuicConnectionEffect effect in effects!)
        {
            if (effect is QuicConnectionDiscardConnectionStateEffect matchingDiscardEffect)
            {
                discardEffect = matchingDiscardEffect;
                break;
            }
        }

        Assert.NotNull(discardEffect);
        Assert.True(endpoint.TryApplyEffect(handle, discardEffect));
    }

}
