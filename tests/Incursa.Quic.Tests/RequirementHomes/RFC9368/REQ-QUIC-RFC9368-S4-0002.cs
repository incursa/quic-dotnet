// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9368-S4-0002")]
public sealed class REQ_QUIC_RFC9368_S4_0002
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAdoptNegotiatedVersion_SwitchesTheClientRuntimeToTheNegotiatedVersionAndUpdatesIncomingInitialProtection()
    {
        using QuicConnectionRuntime runtime = CreateClientRuntime(
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
            QuicVersionNegotiation.Version1);

        Assert.True(runtime.TryAdoptNegotiatedVersion(QuicVersionNegotiation.Version2));

        Assert.Equal(QuicVersionNegotiation.Version2, runtime.VersionProfile.SelectedVersion);
        Assert.Equal(QuicVersionNegotiation.Version2, runtime.VersionProfile.SupportedVersions.Span[0]);
        Assert.Equal(QuicVersionNegotiation.Version1, runtime.VersionProfile.SupportedVersions.Span[1]);

        Assert.NotNull(runtime.InitialPacketProtection);
        Assert.Equal(QuicVersionNegotiation.Version2, runtime.InitialPacketProtection!.Version);

        Assert.True(runtime.TryGetIncomingInitialPacketProtection(
            QuicVersionNegotiation.Version2,
            out QuicInitialPacketProtection negotiatedProtection));
        Assert.Equal(QuicVersionNegotiation.Version2, negotiatedProtection.Version);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAdoptNegotiatedVersion_RejectsUnsupportedOrIncompatibleVersions()
    {
        using QuicConnectionRuntime unsupportedVersionRuntime = CreateClientRuntime(
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
            QuicVersionNegotiation.Version1);

        Assert.False(unsupportedVersionRuntime.TryAdoptNegotiatedVersion(
            QuicVersionNegotiation.CreateReservedVersion(0x10203040)));

        using QuicConnectionRuntime missingCompatibleVersionRuntime = CreateClientRuntime(
            [QuicVersionNegotiation.Version1],
            QuicVersionNegotiation.Version1);

        Assert.False(missingCompatibleVersionRuntime.TryAdoptNegotiatedVersion(QuicVersionNegotiation.Version2));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAdoptNegotiatedVersion_IsANoOpWhenTheNegotiatedVersionMatchesTheCurrentSelection()
    {
        using QuicConnectionRuntime runtime = CreateClientRuntime(
            [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1],
            QuicVersionNegotiation.Version2);

        Assert.True(runtime.TryAdoptNegotiatedVersion(QuicVersionNegotiation.Version2));

        Assert.Equal(QuicVersionNegotiation.Version2, runtime.VersionProfile.SelectedVersion);
        Assert.Equal(QuicVersionNegotiation.Version2, runtime.VersionProfile.SupportedVersions.Span[0]);
        Assert.Equal(QuicVersionNegotiation.Version1, runtime.VersionProfile.SupportedVersions.Span[1]);
        Assert.NotNull(runtime.InitialPacketProtection);
        Assert.Equal(QuicVersionNegotiation.Version2, runtime.InitialPacketProtection!.Version);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCommitPeerTransportParameters_RejectsAChosenVersionThatDoesNotMatchTheNegotiatedVersion()
    {
        using QuicConnectionRuntime runtime = CreateClientRuntime(
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
            QuicVersionNegotiation.Version1);

        Assert.True(runtime.TryAdoptNegotiatedVersion(QuicVersionNegotiation.Version2));

        QuicTransportParameters mismatchedPeerTransportParameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2]);

        PrimeClientRuntimeForPeerTransportParameterCommit(runtime, mismatchedPeerTransportParameters);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 42,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: mismatchedPeerTransportParameters)),
            nowTicks: 42);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.VersionNegotiation, runtime.TerminalState!.Value.Origin);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryAdoptNegotiatedVersion_RekeysOnlyForCompatibleSupportedVersionSetsAcrossRepresentativeOrders()
    {
        (uint[] SupportedVersions, uint InitialVersion, uint NegotiatedVersion, bool ExpectedSuccess, uint ExpectedSelectedVersion)[] scenarios =
        [
            ([QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
                QuicVersionNegotiation.Version1,
                QuicVersionNegotiation.Version2,
                true,
                QuicVersionNegotiation.Version2),
            ([QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1],
                QuicVersionNegotiation.Version2,
                QuicVersionNegotiation.Version1,
                true,
                QuicVersionNegotiation.Version1),
            ([QuicVersionNegotiation.Version1],
                QuicVersionNegotiation.Version1,
                QuicVersionNegotiation.Version2,
                false,
                QuicVersionNegotiation.Version1),
            ([QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
                QuicVersionNegotiation.Version1,
                QuicVersionNegotiation.CreateReservedVersion(0x10203040),
                false,
                QuicVersionNegotiation.Version1),
        ];

        foreach (var scenario in scenarios)
        {
            using QuicConnectionRuntime runtime = CreateClientRuntime(scenario.SupportedVersions, scenario.InitialVersion);

            bool success = runtime.TryAdoptNegotiatedVersion(scenario.NegotiatedVersion);

            Assert.Equal(scenario.ExpectedSuccess, success);
            Assert.Equal(scenario.ExpectedSelectedVersion, runtime.VersionProfile.SelectedVersion);
            Assert.NotNull(runtime.InitialPacketProtection);
            Assert.Equal(scenario.ExpectedSelectedVersion, runtime.InitialPacketProtection!.Version);
        }
    }

    private static QuicConnectionRuntime CreateClientRuntime(uint[] supportedVersions, uint initialVersion)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            supportedVersions: supportedVersions);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialVersion, InitialDestinationConnectionId));
        return runtime;
    }

    private static QuicTransportParameters CreateVersionInformationTransportParameters(
        uint chosenVersion,
        uint[] availableVersions)
    {
        return new QuicTransportParameters
        {
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = chosenVersion,
                AvailableVersions = availableVersions,
            },
        };
    }

    private static void PrimeClientRuntimeForPeerTransportParameterCommit(
        QuicConnectionRuntime runtime,
        QuicTransportParameters peerTransportParameters)
    {
        QuicTransportTlsBridgeState bridge = runtime.TlsState;

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
            HandshakeMessageLength: 48,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)));

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: 48,
            TransportParameters: peerTransportParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
    }
}
