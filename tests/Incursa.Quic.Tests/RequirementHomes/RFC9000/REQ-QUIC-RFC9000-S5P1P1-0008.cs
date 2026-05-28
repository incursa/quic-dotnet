// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0008")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionIdIssuedEvent_RegistersAnEndpointRouteForTheIssuedConnectionId()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.180", RemotePort: 443);
        byte[] issuedConnectionId = [0x60, 0x61, 0x62];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 801UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        Assert.Contains(
            issued.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect register
                && register.ConnectionId == 801UL
                && register.ConnectionIdBytes.ToArray().SequenceEqual(issuedConnectionId));

        ApplyEndpointEffects(endpoint, handle, issued.Effects);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x60, 0x61, 0x62, 0xA1]),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionIdRetiredEvent_RemovesTheEndpointRouteForTheRetiredConnectionId()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.181", RemotePort: 443);
        byte[] issuedConnectionId = [0x64, 0x65, 0x66];
        byte[] routedDatagram = QuicHeaderTestData.BuildShortHeader(0x00, [0x64, 0x65, 0x66, 0xA2]);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 802UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x40),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        ApplyEndpointEffects(endpoint, handle, issued.Effects);

        QuicConnectionIngressResult beforeRetirement = endpoint.ReceiveDatagram(routedDatagram, pathIdentity);
        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, beforeRetirement.Disposition);
        Assert.Equal(handle, beforeRetirement.Handle);

        QuicConnectionTransitionResult retired = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: 802UL),
            nowTicks: 1);

        Assert.True(retired.StateChanged);
        Assert.Contains(
            retired.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retire
                && retire.ConnectionId == 802UL
                && retire.ConnectionIdBytes.ToArray().SequenceEqual(issuedConnectionId));

        ApplyEndpointEffects(endpoint, handle, retired.Effects);

        QuicConnectionIngressResult afterRetirement = endpoint.ReceiveDatagram(routedDatagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, afterRetirement.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, afterRetirement.HandlingKind);
        Assert.Null(afterRetirement.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ConnectionIdIssuedEvent_RoutesTheMaximumLengthIssuedConnectionIdUntilRetirement()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.182", RemotePort: 443);
        byte[] maximumLengthConnectionId = Enumerable.Range(0, QuicConnectionIdKey.MaximumLength)
            .Select(value => (byte)(0x80 + value))
            .ToArray();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 803UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x50),
                ConnectionIdBytes: maximumLengthConnectionId),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        ApplyEndpointEffects(endpoint, handle, issued.Effects);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, maximumLengthConnectionId),
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
