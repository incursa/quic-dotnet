namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6-0002">Discard Unexpected Server-Address Packets</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S9P6-0002")]
public sealed class REQ_QUIC_RFC9000_S9P6_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S9P6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P6-0002")]
    public void ClientDoesNotDiscardPacketsFromThePreferredAddressWhilePreferredAddressMigrationIsInProgress()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());

        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();
        QuicConnectionTransitionResult handshakeDoneResult = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        Assert.Contains(handshakeDoneResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == preferredPath);

        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePathBefore));

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x0A],
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, [0x33, 0x44]),
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            declaredPacketNumberLength: 4);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                preferredPath,
                protectedPacket),
            nowTicks: 30);

        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePathAfter));
        Assert.True(candidatePathAfter.LastActivityTicks > candidatePathBefore.LastActivityTicks);
        Assert.False(candidatePathAfter.Validation.IsAbandoned);
    }
}
