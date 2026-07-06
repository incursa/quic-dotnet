// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Authentication;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_VersionRules_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0895")]
    [Requirement("REQ-QUIC-RFC9000-0896")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void VersionNegotiationPacketFuzz_PreservesUnsigned32BitVersionsAndReservesZero()
    {
        uint[] advertisedVersions =
        [
            QuicVersionNegotiation.Version1,
            0x80000000u,
            0xF0E1D2C3u,
            uint.MaxValue,
        ];
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: advertisedVersions);

        Assert.Equal(0u, QuicVersionNegotiation.VersionNegotiationVersion);
        Assert.True(QuicVersionNegotiation.IsVersionNegotiationVersion(0u));
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.VersionNegotiationVersion,
            [QuicVersionNegotiation.Version1]));
        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket parsed));
        Assert.Equal(advertisedVersions.Length, parsed.SupportedVersionCount);

        for (int index = 0; index < advertisedVersions.Length; index++)
        {
            Assert.Equal(advertisedVersions[index], parsed.GetSupportedVersion(index));
            Assert.True(parsed.ContainsSupportedVersion(advertisedVersions[index]));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0897")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClientOptionsFuzz_RequiresTls13ForVersion1Handshake()
    {
        foreach (SslProtocols unsupportedProtocol in new[] { SslProtocols.Tls12 })
        {
            var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            QuicClientConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint);
            options.ClientAuthenticationOptions.EnabledSslProtocols = unsupportedProtocol;

            NotSupportedException exception = Assert.Throws<NotSupportedException>(() =>
                QuicClientConnectionOptionsValidator.Capture(options, nameof(options)));
            Assert.Contains("Only TLS 1.3 is supported", exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0898")]
    [Requirement("REQ-QUIC-RFC9000-0899")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReservedVersionFuzz_RecognizesFutureIetfAndNegotiationExercisePatterns()
    {
        foreach (uint futureIetfReservedVersion in new uint[] { 0x00000000u, 0x00000001u, 0x00001234u, 0x0000FFFFu })
        {
            Assert.True(QuicVersionNegotiation.IsFutureIetfConsensusReservedVersion(futureIetfReservedVersion));
        }

        foreach (uint ordinaryVersion in new uint[] { 0x00010000u, 0x11223344u, 0x6B3343CFu, 0xFFFFFFFFu })
        {
            Assert.False(QuicVersionNegotiation.IsFutureIetfConsensusReservedVersion(ordinaryVersion));
        }

        foreach (uint template in new uint[] { 0x00112233u, 0x11223344u, 0xF0E0D0C0u })
        {
            uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(template);
            Assert.True(QuicVersionNegotiation.IsReservedVersion(reservedVersion));
            Assert.Equal(0x0A0A0A0Au, reservedVersion & 0x0F0F0F0Fu);
        }

        Assert.False(QuicVersionNegotiation.IsReservedVersion(0x01020304u));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(QuicVersionNegotiation.Version1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0900")]
    [Requirement("REQ-QUIC-RFC9000-0902")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReservedVersionAdvertisementFuzz_AllowsAdvertisingAndClientIgnoresReservedValues()
    {
        foreach (uint template in new uint[] { 0x11223344u, 0x55667788u, 0x99AABBCCu })
        {
            uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(template);
            byte[] packet = new byte[64];

            Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
                QuicVersionNegotiation.Version1,
                [0x10, 0x11],
                [0x20],
                [reservedVersion],
                packet,
                out int bytesWritten));
            Assert.True(QuicPacketParser.TryParseVersionNegotiation(
                packet.AsSpan(0, bytesWritten),
                out QuicVersionNegotiationPacket parsed));

            Assert.Equal(1, parsed.SupportedVersionCount);
            Assert.Equal(reservedVersion, parsed.GetSupportedVersion(0));
            Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
                parsed,
                QuicVersionNegotiation.Version1,
                hasSuccessfullyProcessedAnotherPacket: false));
            Assert.True(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
                parsed,
                QuicVersionNegotiation.Version1,
                [QuicVersionNegotiation.Version1],
                hasSuccessfullyProcessedAnotherPacket: false));
        }
    }
}
