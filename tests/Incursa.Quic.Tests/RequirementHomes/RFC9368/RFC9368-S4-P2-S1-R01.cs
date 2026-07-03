// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("RFC9368-S4-P2-S1-R01")]
public sealed class REQ_QUIC_RFC9368_S4_0001
{
    private static readonly uint[] ClientSupportedVersions =
    [
        QuicVersionNegotiation.Version1,
        QuicVersionNegotiation.Version2,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectAsync_NegotiatesVersion2WhenBothEndpointsOfferCompatibleVersionsAndPreservesOriginalAndNegotiatedInitialProtections()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            clientOptions,
            detachedResumptionTicketSnapshot: null,
            supportedVersions: ClientSupportedVersions).AsTask();

        Task completionTask = Task.WhenAll(acceptTask, connectTask);
        Task completedTask = await Task.WhenAny(completionTask, Task.Delay(TimeSpan.FromSeconds(5)));
        if (completedTask != completionTask)
        {
            throw new TimeoutException("RFC 9368 loopback negotiation did not complete within 5 seconds.");
        }

        await completionTask;

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            QuicConnectionRuntime serverRuntime = GetRuntime(serverConnection);
            QuicConnectionRuntime clientRuntime = GetRuntime(clientConnection);

            Assert.Equal(QuicVersionNegotiation.Version2, serverRuntime.VersionProfile.SelectedVersion);
            Assert.Equal(QuicVersionNegotiation.Version2, clientRuntime.VersionProfile.SelectedVersion);

            Assert.NotNull(serverRuntime.PeerInitialPacketProtection);
            Assert.Equal(QuicVersionNegotiation.Version1, serverRuntime.PeerInitialPacketProtection!.Version);
            Assert.NotNull(serverRuntime.InitialPacketProtection);
            Assert.Equal(QuicVersionNegotiation.Version2, serverRuntime.InitialPacketProtection!.Version);

            Assert.NotNull(clientRuntime.InitialPacketProtection);
            Assert.Equal(QuicVersionNegotiation.Version2, clientRuntime.InitialPacketProtection!.Version);

            Assert.True(serverRuntime.TryGetIncomingInitialPacketProtection(
                QuicVersionNegotiation.Version1,
                out QuicInitialPacketProtection originalProtection));
            Assert.Equal(QuicVersionNegotiation.Version1, originalProtection.Version);

            Assert.True(serverRuntime.TryGetIncomingInitialPacketProtection(
                QuicVersionNegotiation.Version2,
                out QuicInitialPacketProtection negotiatedProtection));
            Assert.Equal(QuicVersionNegotiation.Version2, negotiatedProtection.Version);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectCompatibleVersion_RejectsMissingOrIncompatibleVersionSets()
    {
        Assert.False(QuicVersionNegotiation.TrySelectCompatibleVersion(
            QuicVersionNegotiation.Version1,
            [],
            [QuicVersionNegotiation.Version1],
            out _));

        Assert.False(QuicVersionNegotiation.TrySelectCompatibleVersion(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            [],
            out _));

        Assert.False(QuicVersionNegotiation.TrySelectCompatibleVersion(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            [QuicVersionNegotiation.CreateReservedVersion(0x10203040)],
            out _));

        Assert.False(QuicVersionNegotiation.TrySelectCompatibleVersion(
            0x11223344,
            [0x11223344],
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectCompatibleVersion_FallsBackToTheOriginalVersionWhenItIsTheOnlyMutuallySupportedVersion()
    {
        Assert.True(QuicVersionNegotiation.TrySelectCompatibleVersion(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1],
            out uint selectedVersion));

        Assert.Equal(QuicVersionNegotiation.Version1, selectedVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TrySelectCompatibleVersion_RespectsCompatibilityAndServerOrderingAcrossRepresentativeVersionSets()
    {
        (uint ClientOriginalVersion, uint[] ClientAvailableVersions, uint[] ServerSupportedVersions, bool ExpectedSuccess, uint ExpectedSelectedVersion)[] scenarios =
        [
            (QuicVersionNegotiation.Version1,
                [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
                [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
                true,
                QuicVersionNegotiation.Version2),
            (QuicVersionNegotiation.Version1,
                [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
                [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1],
                true,
                QuicVersionNegotiation.Version2),
            (QuicVersionNegotiation.Version2,
                [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
                [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
                true,
                QuicVersionNegotiation.Version1),
            (QuicVersionNegotiation.Version2,
                [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2],
                [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1],
                true,
                QuicVersionNegotiation.Version1),
            (QuicVersionNegotiation.Version1,
                [QuicVersionNegotiation.Version1],
                [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1],
                true,
                QuicVersionNegotiation.Version1),
            (QuicVersionNegotiation.Version1,
                [QuicVersionNegotiation.Version1],
                [QuicVersionNegotiation.Version2],
                false,
                default),
        ];

        foreach (var scenario in scenarios)
        {
            bool success = QuicVersionNegotiation.TrySelectCompatibleVersion(
                scenario.ClientOriginalVersion,
                scenario.ClientAvailableVersions,
                scenario.ServerSupportedVersions,
                out uint selectedVersion);

            Assert.Equal(scenario.ExpectedSuccess, success);
            if (success)
            {
                Assert.Equal(scenario.ExpectedSelectedVersion, selectedVersion);
            }
        }
    }

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        return connection.Runtime;
    }
}
