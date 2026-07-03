// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S10-3-1-P3-S1-R01">An endpoint MUST NOT check for any stateless reset tokens associated with connection IDs it has not used or for connection IDs that have been retired.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-3-1-P3-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreateStatelessResetDatagram_RejectsUnusedConnectionIds()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.142", RemotePort: 443);
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0xD0);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 403UL,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        Assert.Contains(
            issued.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect register && register.ConnectionId == 403UL);

        foreach (QuicConnectionEffect effect in issued.Effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }

        QuicConnectionStatelessResetEmissionResult emissionResult = endpoint.TryCreateStatelessResetDatagram(
            handle,
            404UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.False(emissionResult.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emissionResult.Disposition);
        Assert.Null(emissionResult.PathIdentity);
        Assert.True(emissionResult.Datagram.IsEmpty);
    }
}
