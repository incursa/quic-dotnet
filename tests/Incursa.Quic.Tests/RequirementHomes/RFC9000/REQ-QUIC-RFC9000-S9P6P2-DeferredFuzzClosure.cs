// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S9P6P2_DeferredFuzzClosure
{
    private static readonly QuicConnectionPathIdentity OriginalPath = new("203.0.113.69", RemotePort: 443);
    private static readonly byte[] PacketNumber = [0x00, 0x00, 0x00, 0x07];
    private static readonly byte[] InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
    private static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    private static readonly byte[] PreferredIpv4Address = [198, 51, 100, 69];
    private static readonly byte[] PreferredIpv6Address =
    [
        0x20, 0x01, 0x0D, 0xB8,
        0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x45,
    ];
    private static readonly byte[] PreferredStatelessResetToken =
    [
        0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
    ];
    private static readonly QuicConnectionPathIdentity PreferredPath = new(
        new IPAddress(PreferredIpv4Address).ToString(),
        RemotePort: 9469);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreferredAddressSnapshotFuzz_KeepsValuesBoundedToEachConnection()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            byte[] expectedInitialSourceConnectionId = [0x10, 0x11, 0x12, (byte)(0x20 + iteration)];
            byte[] expectedPreferredIpv4Address = [198, 51, 100, (byte)(100 + iteration)];
            byte[] expectedPreferredIpv6Address =
            [
                0x20, 0x01, 0x0D, 0xB8,
                0x00, 0x01, 0x00, 0x02,
                0x00, 0x03, 0x00, 0x04,
                0x00, 0x05, 0x00, (byte)(0x70 + iteration),
            ];
            byte[] expectedPreferredConnectionId = [0x40, 0x41, 0x42, (byte)(0x50 + iteration)];
            byte[] expectedStatelessResetToken = Enumerable
                .Range(0, QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength)
                .Select(value => (byte)(0x60 + iteration + value))
                .ToArray();

            QuicTransportParameters source = new()
            {
                InitialSourceConnectionId = expectedInitialSourceConnectionId.ToArray(),
                PreferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                    preferredConnectionId: expectedPreferredConnectionId.ToArray(),
                    preferredIpv4Address: expectedPreferredIpv4Address.ToArray(),
                    preferredIpv4Port: (ushort)(9443 + iteration),
                    preferredIpv6Address: expectedPreferredIpv6Address.ToArray(),
                    preferredIpv6Port: (ushort)(9553 + iteration),
                    statelessResetToken: expectedStatelessResetToken.ToArray()),
            };

            QuicConnectionRuntime firstRuntime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
            QuicConnectionRuntime secondRuntime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
            QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(firstRuntime, source);
            QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(secondRuntime, source);

            QuicTransportParameters firstCommitted = firstRuntime.TlsState.PeerTransportParameters!;
            QuicTransportParameters secondCommitted = secondRuntime.TlsState.PeerTransportParameters!;
            QuicTransportParameters firstSnapshot = Assert.IsType<QuicTransportParameters>(firstRuntime.TlsState.PeerTransportParametersSnapshot);
            QuicTransportParameters secondSnapshot = Assert.IsType<QuicTransportParameters>(secondRuntime.TlsState.PeerTransportParametersSnapshot);

            source.InitialSourceConnectionId![0] = 0xEE;
            source.PreferredAddress!.IPv4Address[0] = 0xDD;
            firstCommitted.InitialSourceConnectionId![0] = 0xCC;
            firstCommitted.PreferredAddress!.ConnectionId[0] = 0xBB;
            firstCommitted.PreferredAddress.StatelessResetToken[0] = 0xAA;

            AssertPreferredAddressSnapshot(secondCommitted, expectedInitialSourceConnectionId, expectedPreferredIpv4Address, expectedPreferredIpv6Address, expectedPreferredConnectionId, expectedStatelessResetToken);
            AssertPreferredAddressSnapshot(firstSnapshot, expectedInitialSourceConnectionId, expectedPreferredIpv4Address, expectedPreferredIpv6Address, expectedPreferredConnectionId, expectedStatelessResetToken);
            AssertPreferredAddressSnapshot(secondSnapshot, expectedInitialSourceConnectionId, expectedPreferredIpv4Address, expectedPreferredIpv6Address, expectedPreferredConnectionId, expectedStatelessResetToken);
            Assert.NotSame(firstCommitted.PreferredAddress, secondCommitted.PreferredAddress);
            Assert.NotSame(firstSnapshot.PreferredAddress, secondSnapshot.PreferredAddress);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreferredAddressPathChallengeFuzz_RespondsWithMatchingPathResponseOnThatPath()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            using QuicConnectionRuntime runtime = CreateRuntime();
            byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData((byte)(0x42 + iteration));
            byte[] protectedPacket = BuildProtectedPathChallengePacket(runtime, challengeData);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    PreferredPath,
                    protectedPacket),
                nowTicks: 20 + iteration);

            Assert.True(result.StateChanged);
            QuicConnectionSendDatagramEffect response = QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
                runtime,
                result,
                PreferredPath,
                challengeData,
                expectMinimumSize: false);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(OriginalPath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(PreferredPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            Assert.True(QuicS8P2PathValidationTestSupport.TryOpenPathChallengePayload(
                runtime,
                response.Datagram.Span,
                out QuicPathChallengeFrame pathChallenge,
                out _,
                out _));
            Assert.True(candidatePath.Validation.ChallengePayload.Span.SequenceEqual(pathChallenge.Data));
        }
    }

    private static void AssertPreferredAddressSnapshot(
        QuicTransportParameters parameters,
        byte[] expectedInitialSourceConnectionId,
        byte[] expectedPreferredIpv4Address,
        byte[] expectedPreferredIpv6Address,
        byte[] expectedPreferredConnectionId,
        byte[] expectedStatelessResetToken)
    {
        Assert.Equal(expectedInitialSourceConnectionId, parameters.InitialSourceConnectionId);
        Assert.NotNull(parameters.PreferredAddress);
        Assert.Equal(expectedPreferredIpv4Address, parameters.PreferredAddress!.IPv4Address);
        Assert.Equal(expectedPreferredIpv6Address, parameters.PreferredAddress.IPv6Address);
        Assert.Equal(expectedPreferredConnectionId, parameters.PreferredAddress.ConnectionId);
        Assert.Equal(expectedStatelessResetToken, parameters.PreferredAddress.StatelessResetToken);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(OriginalPath);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            CreatePeerTransportParameters());
        return runtime;
    }

    private static byte[] BuildProtectedPathChallengePacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> challengeData)
    {
        byte[] applicationPayload = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        return QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            PacketNumber,
            applicationPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            declaredPacketNumberLength: PacketNumber.Length);
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = PreferredIpv4Address,
                IPv4Port = 9469,
                IPv6Address = PreferredIpv6Address,
                IPv6Port = 9569,
                ConnectionId = PreferredConnectionId,
                StatelessResetToken = PreferredStatelessResetToken,
            },
        };
    }
}
