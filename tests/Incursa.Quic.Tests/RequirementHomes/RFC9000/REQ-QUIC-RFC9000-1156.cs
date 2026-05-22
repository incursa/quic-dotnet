namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1156")]
public sealed class REQ_QUIC_RFC9000_1156
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerTransportParametersCommitted_WithInvalidPreferredAddressClosesWithTransportParameterError()
    {
        QuicTransportParameters invalidPeerParameters =
            QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters(
                preferredConnectionId: QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(
            QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId));
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(runtime, invalidPeerParameters);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: invalidPeerParameters)),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.TransportParameterError, runtime.TerminalState.Value.Close.TransportErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1156")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsInvalidPreferredAddressWhenParsingAsClient()
    {
        byte[] preferredIpv4Address = [192, 0, 2, 1];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06];
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            preferredIpv4Address,
            9447,
            preferredIpv6Address,
            9557,
            [],
            Enumerable.Range(0, 16).Select(value => (byte)(0x70 + value)).ToArray());

        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }
}
