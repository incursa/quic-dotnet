// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S10-3-1-P2-S2-R01">Endpoints MAY skip this check if any packet from a datagram is successfully processed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-3-1-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("RFC9000-S10-3-1-P2-S2-R01")]
    public void ReceiveDatagram_PrefersSuccessfullyProcessedMinimumRoutablePacketOverPotentialStatelessResetTail()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.93");
        byte[] routeConnectionId =
        [
            0x66, 0x01, 0xA0, 0x03,
            0xB0, 0x03, 0xC0, 0x03,
        ];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x93);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 103UL));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 103UL, token));

        byte[] routedPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            routeConnectionId,
            triggeringPacketLength: 2 + routeConnectionId.Length);
        byte[] potentialResetTail = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        byte[] coalescedDatagram = [.. routedPacket, .. potentialResetTail];

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(coalescedDatagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
