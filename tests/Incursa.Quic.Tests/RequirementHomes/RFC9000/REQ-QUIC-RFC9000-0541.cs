namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0541")]
public sealed class REQ_QUIC_RFC9000_0541
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PreferredAddressPacketsAreClassifiedAsMigrationCandidatesBeforeTheyAreTrusted()
    {
        byte[] initialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] preferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] statelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
        byte[] preferredIpv4Address = [198, 51, 100, 30];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x1E];
        QuicTransportParameters transportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = 9443,
                IPv6Address = preferredIpv6Address,
                IPv6Port = 9553,
                ConnectionId = preferredConnectionId,
                StatelessResetToken = statelessResetToken,
            },
        };

        Span<byte> destination = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));

        Assert.NotNull(parsedTransportParameters.PreferredAddress);

        QuicConnectionPathIdentity activePath = new("203.0.113.30", RemotePort: 443);
        QuicConnectionPathIdentity preferredPath = new("198.51.100.30", RemotePort: 9443);
        QuicRecordingDiagnosticsSink diagnosticsSink = new();
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
            activePath,
            parsedTransportParameters,
            diagnosticsSink);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                preferredPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.AddressChangeClassified
            && diagnosticEvent.PathIdentity == preferredPath
            && diagnosticEvent.PathClassification == QuicConnectionPathClassification.MigrationCandidate);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            preferredPath,
            runtime: runtime);
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidatedPreferredAddressPacketsAreNotClassifiedAsMigrationCandidates()
    {
        QuicTransportParameters transportParameters = new()
        {
            InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [198, 51, 100, 30],
                IPv4Port = 9443,
                IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x1E],
                IPv6Port = 9553,
                ConnectionId = [0x20, 0x21, 0x22, 0x23],
                StatelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F],
            },
        };
        QuicConnectionPathIdentity activePath = new("203.0.113.30", RemotePort: 443);
        QuicConnectionPathIdentity preferredPath = new("198.51.100.30", RemotePort: 9443);
        QuicRecordingDiagnosticsSink diagnosticsSink = new();
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
            activePath,
            transportParameters,
            diagnosticsSink);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        _ = runtime.Transition(new QuicConnectionPacketReceivedEvent(20, preferredPath, datagram), nowTicks: 20);
        _ = QuicPathMigrationRecoveryTestSupport.ValidatePath(runtime, preferredPath, observedAtTicks: 30);
        int diagnosticsCount = diagnosticsSink.Events.Count;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                preferredPath,
                datagram),
            nowTicks: 40);

        QuicS9P6P1PreferredAddressTestSupport.AssertNoPathChallengeSent(result);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(preferredPath));
        Assert.Equal(diagnosticsCount, diagnosticsSink.Events.Count);
    }
}
