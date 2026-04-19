namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P3-0003">Clients MUST retain other connection state, in particular cryptographic handshake messages.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P3-0003")]
public sealed class REQ_QUIC_RFC9002_S6P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateConnectionIdBindings_AcceptsMatchingRetrySourceConnectionIdAfterRetry()
    {
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = [0x10, 0x11],
            InitialSourceConnectionId = [0x20, 0x21],
            RetrySourceConnectionId = [0x30, 0x31],
        };

        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            initialDestinationConnectionId: [0x10, 0x11],
            initialSourceConnectionId: [0x20, 0x21],
            usedRetry: true,
            retrySourceConnectionId: [0x30, 0x31],
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRetryReplayInitialPacketsPreserveTheOriginalHandshakeMessageBytes()
    {
        using QuicConnectionRuntime clientRuntime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        byte[] originalClientHelloBytes = QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(clientRuntime);

        QuicConnectionTransitionResult retryResult = clientRuntime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket[] replayPackets =
            QuicS17P2P5P3TestSupport.ReadRetryReplayInitialPackets(
                retryResult,
                QuicS17P2P5P3TestSupport.CreateServerProtection());

        Assert.NotEmpty(replayPackets);

        ulong expectedOffset = 0;
        foreach (QuicS17P2P5P3TestSupport.RetryReplayInitialPacket replayPacket in replayPackets)
        {
            Assert.Equal(expectedOffset, replayPacket.CryptoOffset);
            Assert.True(originalClientHelloBytes.AsSpan(
                checked((int)replayPacket.CryptoOffset),
                replayPacket.CryptoPayload.Length).SequenceEqual(replayPacket.CryptoPayload));
            expectedOffset += (ulong)replayPacket.CryptoPayload.Length;
        }

        Assert.Equal((ulong)originalClientHelloBytes.Length, expectedOffset);
    }
}
