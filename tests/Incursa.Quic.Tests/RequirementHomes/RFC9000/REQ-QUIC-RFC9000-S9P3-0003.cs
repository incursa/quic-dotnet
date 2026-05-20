namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0003")]
public sealed class REQ_QUIC_RFC9000_S9P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationTrafficToAnUnvalidatedPeerAddressIsPaddedToTheMinimumDatagramSize()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.102", RemotePort: 443);
        QuicConnectionPathIdentity unvalidatedPath = new("203.0.113.103", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                unvalidatedPath,
                datagram),
            nowTicks: 20);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            unvalidatedPath,
            runtime: runtime);
    }
}
