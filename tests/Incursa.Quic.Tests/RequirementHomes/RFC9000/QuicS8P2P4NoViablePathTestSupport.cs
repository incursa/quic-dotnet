namespace Incursa.Quic.Tests;

internal static class QuicS8P2P4NoViablePathTestSupport
{
    internal static (QuicConnectionRuntime Runtime, QuicConnectionPathIdentity ActivePath, QuicConnectionPathIdentity CandidatePath) CreateRuntimeWithCandidatePath(
        string activeAddress,
        string candidateAddress,
        bool validateActivePath)
    {
        QuicConnectionPathIdentity activePath = new(activeAddress, RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new(candidateAddress, RemotePort: 443);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                activePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 2).StateChanged);

        if (validateActivePath)
        {
            Assert.True(runtime.TryMarkPeerAddressValidatedByAddressValidationToken(nowTicks: 3));
        }

        Assert.True(QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20).StateChanged);

        return (runtime, activePath, candidatePath);
    }
}
