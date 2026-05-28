// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P2-0003">An endpoint that uses this design MUST either use the same connection ID length for all connections or encode the length of the connection ID such that it can be recovered without state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P2-0003")]
public sealed class REQ_QUIC_RFC9000_S10P3P2_0003
{
    private static readonly QuicConnectionPathIdentity PathIdentity = new("203.0.113.82", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StatelessResetLookup_RecoversDistinctConnectionIdLengthsWithoutExternalState()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1, maximumStatelessResetEmissionsPerRemoteAddress: 2);
        using QuicConnectionRuntime shortRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime longRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle shortHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle longHandle = endpoint.AllocateConnectionHandle();

        byte[] shortRouteConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] longRouteConnectionId = [0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24];
        byte[] shortToken = QuicStatelessResetRequirementTestData.CreateToken(0x91);
        byte[] longToken = QuicStatelessResetRequirementTestData.CreateToken(0xA1);

        Assert.True(QuicConnectionIdKey.TryCreate(shortRouteConnectionId, out QuicConnectionIdKey shortRouteKey));
        Assert.Equal((byte)shortRouteConnectionId.Length, shortRouteKey.Length);
        Assert.True(QuicConnectionIdKey.TryCreate(longRouteConnectionId, out QuicConnectionIdKey longRouteKey));
        Assert.Equal((byte)longRouteConnectionId.Length, longRouteKey.Length);

        QuicStatelessResetEndpointHostTestSupport.ConfigureDiscardedRetainedRouteEndpoint(
            endpoint,
            shortRuntime,
            shortHandle,
            PathIdentity,
            shortRouteConnectionId,
            resetConnectionId: 401UL,
            token: shortToken,
            enteredAtTicks: 1);

        QuicStatelessResetEndpointHostTestSupport.ConfigureDiscardedRetainedRouteEndpoint(
            endpoint,
            longRuntime,
            longHandle,
            PathIdentity,
            longRouteConnectionId,
            resetConnectionId: 402UL,
            token: longToken,
            enteredAtTicks: 2);

        byte[] shortTriggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            shortRouteConnectionId,
            triggeringPacketLength: 80);
        byte[] longTriggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            longRouteConnectionId,
            triggeringPacketLength: 84);

        QuicConnectionStatelessResetEmissionResult shortEmission = endpoint.TryCreateStatelessResetDatagramForPacket(
            shortTriggeringPacket,
            PathIdentity,
            hasLoopPreventionState: true);
        QuicConnectionStatelessResetEmissionResult longEmission = endpoint.TryCreateStatelessResetDatagramForPacket(
            longTriggeringPacket,
            PathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, shortEmission.Disposition);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, longEmission.Disposition);
        Assert.Equal(PathIdentity, shortEmission.PathIdentity);
        Assert.Equal(PathIdentity, longEmission.PathIdentity);
        Assert.Equal(shortTriggeringPacket.Length - 1, shortEmission.Datagram.Length);
        Assert.Equal(longTriggeringPacket.Length - 1, longEmission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(shortEmission.Datagram.Span, shortToken);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(longEmission.Datagram.Span, longToken);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StatelessResetLookup_DoesNotCrossMatchDifferentConnectionIdLengths()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        byte[] shortRoutePrefix = [0x31, 0x32, 0x33, 0x34];
        byte[] longRouteConnectionId = [0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xB1);

        QuicStatelessResetEndpointHostTestSupport.ConfigureDiscardedRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            PathIdentity,
            longRouteConnectionId,
            resetConnectionId: 403UL,
            token: token,
            enteredAtTicks: 3);

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            shortRoutePrefix,
            triggeringPacketLength: 80);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            PathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void StatelessResetLookup_HandlesMaximumConnectionIdLengthWithoutLosingLengthInformation()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(3, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        byte[] maximumRouteConnectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(
            start: 0xC1,
            length: QuicConnectionIdKey.MaximumLength);
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC1);

        Assert.True(QuicConnectionIdKey.TryCreate(maximumRouteConnectionId, out QuicConnectionIdKey routeKey));
        Assert.Equal((byte)QuicConnectionIdKey.MaximumLength, routeKey.Length);

        QuicStatelessResetEndpointHostTestSupport.ConfigureDiscardedRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            PathIdentity,
            maximumRouteConnectionId,
            resetConnectionId: 404UL,
            token: token,
            enteredAtTicks: 4);

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            maximumRouteConnectionId,
            triggeringPacketLength: 88);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringPacket,
            PathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(88 - 1, emission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
    }
}
