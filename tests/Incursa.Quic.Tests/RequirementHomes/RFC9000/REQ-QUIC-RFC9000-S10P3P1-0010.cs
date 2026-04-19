namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P1-0010">An endpoint MUST remember all stateless reset tokens associated with connection IDs and remote addresses for datagrams it has recently sent, including Stateless Reset Token field values from NEW_CONNECTION_ID frames and the server's transport parameters, and excluding tokens associated with connection IDs that are unused or retired.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P1-0010")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCommitLocalTransportParameters_ClonesTheServerStatelessResetTokenValue()
    {
        byte[] expectedStatelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0xA0);
        byte[] sourceStatelessResetToken = expectedStatelessResetToken.ToArray();
        QuicTransportParameters localTransportParameters = new()
        {
            StatelessResetToken = sourceStatelessResetToken,
        };
        QuicTransportTlsBridgeState state = new(QuicTlsRole.Server);

        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: localTransportParameters)));

        Assert.NotSame(localTransportParameters, state.LocalTransportParameters);
        Assert.NotSame(sourceStatelessResetToken, state.LocalTransportParameters!.StatelessResetToken);
        Assert.Equal(expectedStatelessResetToken, state.LocalTransportParameters.StatelessResetToken);

        sourceStatelessResetToken[0] = 0xFF;

        Assert.Equal(expectedStatelessResetToken, state.LocalTransportParameters.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionIdIssuedEvent_RegistersTheIssuedStatelessResetTokenForEmission()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.140", RemotePort: 443);
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0xB0);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 401UL,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        Assert.Contains(
            issued.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect register && register.ConnectionId == 401UL);

        foreach (QuicConnectionEffect effect in issued.Effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }

        QuicConnectionStatelessResetEmissionResult emissionResult = endpoint.TryCreateStatelessResetDatagram(
            handle,
            401UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.True(emissionResult.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emissionResult.Disposition);
        Assert.Equal(pathIdentity, emissionResult.PathIdentity);
        Assert.Equal(99, emissionResult.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(emissionResult.Datagram.Span));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emissionResult.Datagram.Span, statelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionIdRetiredEvent_RemovesTheRetiredStatelessResetTokenFromEmission()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.141", RemotePort: 443);
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0xC0);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 402UL,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        Assert.Contains(
            issued.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect register && register.ConnectionId == 402UL);

        foreach (QuicConnectionEffect effect in issued.Effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }

        QuicConnectionTransitionResult retired = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: 402UL),
            nowTicks: 1);

        Assert.True(retired.StateChanged);
        Assert.Contains(
            retired.Effects,
            effect => effect is QuicConnectionRetireStatelessResetTokenEffect retire && retire.ConnectionId == 402UL);

        foreach (QuicConnectionEffect effect in retired.Effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }

        QuicConnectionStatelessResetEmissionResult emissionResult = endpoint.TryCreateStatelessResetDatagram(
            handle,
            402UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.False(emissionResult.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emissionResult.Disposition);
        Assert.Null(emissionResult.PathIdentity);
        Assert.True(emissionResult.Datagram.IsEmpty);
    }
}
