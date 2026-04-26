namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0009">After AEAD-limit terminal discard, an endpoint MUST suppress stateless-reset response emission when a later received packet does not resolve to a retained route or resolves only to route state without a remembered stateless-reset token for the same remote address and port.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0009")]
public sealed class REQ_QUIC_RFC9001_S6P6_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointSuppressesStatelessResetForUnknownRetainedRouteAfterAeadLimitDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] retainedRouteConnectionId = [0x66, 0x09, 0xA0, 0x01];
        byte[] unknownRouteConnectionId = [0x66, 0x09, 0xA0, 0x02];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xE1);

        ConfigureDiscardedRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            pathIdentity,
            retainedRouteConnectionId,
            6609UL,
            token,
            enteredAtTicks: 1);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            CreateRetainedRouteShortHeaderDatagram(unknownRouteConnectionId, triggeringPacketLength: 76),
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointSuppressesStatelessResetForRouteWithoutRememberedTokenAfterAeadLimitDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x09, 0xA0, 0x03];

        ConfigureDiscardedEndpointWithoutRememberedToken(
            endpoint,
            runtime,
            handle,
            pathIdentity,
            routeConnectionId,
            6609UL,
            enteredAtTicks: 2);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 78),
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointStillEmitsRetainedRouteResponseWhenRouteAndTokenMatch()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] routeConnectionId = [0x66, 0x09, 0xA0, 0x04];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xE4);

        ConfigureDiscardedRetainedRouteEndpoint(
            endpoint,
            runtime,
            handle,
            pathIdentity,
            routeConnectionId,
            6609UL,
            token,
            enteredAtTicks: 3);

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
            CreateRetainedRouteShortHeaderDatagram(routeConnectionId, triggeringPacketLength: 80),
            pathIdentity,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(pathIdentity, emission.PathIdentity);
        Assert.Equal(79, emission.Datagram.Length);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzEndpointSuppressesNonRetainedRouteOrMissingTokenAfterAeadLimitDiscard()
    {
        Random random = new(unchecked((int)0x9001_6609));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
            QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new(
                "203.0.113.69",
                "198.51.100.69",
                6609,
                4433);
            byte[] retainedRouteConnectionId = [0x66, 0x09, unchecked((byte)iteration), 0x01];
            byte[] unknownRouteConnectionId = [0x66, 0x09, unchecked((byte)iteration), 0x02];
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0xE0 + iteration));
            bool useKnownRoute = random.Next(0, 2) == 0;
            bool rememberToken = random.Next(0, 2) == 0;
            int triggeringPacketLength = QuicStatelessReset.MinimumDatagramLength + 8 + random.Next(0, 16);

            if (useKnownRoute)
            {
                if (rememberToken)
                {
                    ConfigureDiscardedRetainedRouteEndpoint(
                        endpoint,
                        runtime,
                        handle,
                        pathIdentity,
                        retainedRouteConnectionId,
                        (ulong)(7609 + iteration),
                        token,
                        enteredAtTicks: iteration + 1);
                }
                else
                {
                    ConfigureDiscardedEndpointWithoutRememberedToken(
                        endpoint,
                        runtime,
                        handle,
                        pathIdentity,
                        retainedRouteConnectionId,
                        (ulong)(7609 + iteration),
                        enteredAtTicks: iteration + 1);
                }
            }
            else
            {
                ConfigureDiscardedRetainedRouteEndpoint(
                    endpoint,
                    runtime,
                    handle,
                    pathIdentity,
                    retainedRouteConnectionId,
                    (ulong)(7609 + iteration),
                    token,
                    enteredAtTicks: iteration + 1);
            }

            byte[] triggeringPacket = CreateRetainedRouteShortHeaderDatagram(
                useKnownRoute ? retainedRouteConnectionId : unknownRouteConnectionId,
                triggeringPacketLength);

            QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
                triggeringPacket,
                pathIdentity,
                hasLoopPreventionState: true);

            if (!useKnownRoute || !rememberToken)
            {
                Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
                Assert.False(emission.Emitted);
                Assert.True(emission.Datagram.IsEmpty);
                continue;
            }

            Assert.True(emission.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
        }
    }

    private static void ConfigureDiscardedRetainedRouteEndpoint(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> routeConnectionId,
        ulong resetConnectionId,
        ReadOnlySpan<byte> token,
        int enteredAtTicks)
    {
        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: resetConnectionId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, resetConnectionId, token));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState(enteredAtTicks))));
    }

    private static void ConfigureDiscardedEndpointWithoutRememberedToken(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> routeConnectionId,
        ulong resetConnectionId,
        int enteredAtTicks)
    {
        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: resetConnectionId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState(enteredAtTicks))));
    }

    private static byte[] CreateRetainedRouteShortHeaderDatagram(
        ReadOnlySpan<byte> routeConnectionId,
        int triggeringPacketLength)
    {
        Assert.True(triggeringPacketLength > 1 + routeConnectionId.Length);

        byte[] remainder = new byte[triggeringPacketLength - 1];
        routeConnectionId.CopyTo(remainder);
        for (int offset = routeConnectionId.Length; offset < remainder.Length; offset++)
        {
            remainder[offset] = unchecked((byte)(0xA0 + offset));
        }

        return QuicHeaderTestData.BuildShortHeader(0x00, remainder);
    }

    private static QuicConnectionTerminalState CreateAeadLimitTerminalState(int enteredAtTicks)
    {
        return new QuicConnectionTerminalState(
            QuicConnectionPhase.Discarded,
            QuicConnectionCloseOrigin.Local,
            new QuicConnectionCloseMetadata(
                QuicTransportErrorCode.AeadLimitReached,
                ApplicationErrorCode: null,
                TriggeringFrameType: null,
                ReasonPhrase: "The connection reached the AEAD limit."),
            enteredAtTicks);
    }
}
