namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6-0001">If a client receives packets from a new server address when the client has not initiated a migration to that address, the client SHOULD discard these packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S9P6-0001")]
public sealed class REQ_QUIC_RFC9000_S9P6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S9P6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P6-0002")]
    public void ClientDiscardsPacketsFromAnUnexpectedServerAddressWhenMigrationHasNotBeenInitiated()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path);

        QuicConnectionPathIdentity unexpectedServerPath = new("203.0.113.99", RemotePort: 9443);
        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x09],
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, [0x11, 0x22]),
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            declaredPacketNumberLength: 4);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                unexpectedServerPath,
                protectedPacket),
            nowTicks: 20);

        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(unexpectedServerPath));
        Assert.False(runtime.RecentlyValidatedPaths.ContainsKey(unexpectedServerPath));
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == unexpectedServerPath);
    }
}
