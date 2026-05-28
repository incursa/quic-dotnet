// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0009")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveIssuedConnectionId_RoutesShortHeaderPacketsAtAnyTime()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.183", RemotePort: 443);
        byte[] issuedConnectionId = [0x90, 0x91, 0x92];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 901UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x60),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        ApplyEndpointEffects(endpoint, handle, issued.Effects);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x90, 0x91, 0x92, 0xA1]),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveIssuedConnectionId_RoutesLongHeaderPacketsAtAnyTime()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.184", RemotePort: 443);
        byte[] issuedConnectionId = [0x94, 0x95, 0x96];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 902UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        ApplyEndpointEffects(endpoint, handle, issued.Effects);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
                destinationConnectionId: issuedConnectionId,
                sourceConnectionId: [0x20],
                protectedPayload: [0xA1]),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(handle, result.Handle);
    }

    private static void ApplyEndpointEffects(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionHandle handle,
        IEnumerable<QuicConnectionEffect> effects)
    {
        foreach (QuicConnectionEffect effect in effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }
    }
}
