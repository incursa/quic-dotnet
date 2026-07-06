// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S17P2P5_RetryConnectionId_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9000-S17-2-5-1-P2-S1-R01")]
    [Requirement("RFC9000-S17-2-5-1-P2-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetrySourceConnectionIdFuzz_RejectsClientInitialDestinationIdAndPreservesDistinctServerChoice()
    {
        byte[][] originalDestinationConnectionIds =
        [
            [0x11],
            [0x11, 0x12, 0x13, 0x14],
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
        ];
        byte[][] retrySourceConnectionIds =
        [
            [0x31],
            [0x31, 0x32, 0x33, 0x34],
            [0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58],
        ];

        foreach (byte[] originalDestinationConnectionId in originalDestinationConnectionIds)
        {
            foreach (byte[] retrySourceConnectionId in retrySourceConnectionIds)
            {
                byte[] retryDestinationConnectionId = CreateConnectionId(0x20, retrySourceConnectionId.Length);
                byte[] retryToken = CreateConnectionId(0x70, retrySourceConnectionId.Length + 1);

                Assert.False(QuicRetryIntegrity.TryBuildRetryPacket(
                    originalDestinationConnectionId,
                    retryDestinationConnectionId,
                    originalDestinationConnectionId,
                    retryToken,
                    out byte[] rejectedRetryPacket));
                Assert.Empty(rejectedRetryPacket);

                Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
                    originalDestinationConnectionId,
                    retryDestinationConnectionId,
                    retrySourceConnectionId,
                    retryToken,
                    out byte[] retryPacket));
                Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
                    originalDestinationConnectionId,
                    retryPacket));
                Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket header));
                Assert.Equal(retrySourceConnectionId, header.SourceConnectionId.ToArray());
                Assert.NotEqual(originalDestinationConnectionId, header.SourceConnectionId.ToArray());
            }
        }
    }

    [Fact]
    [Requirement("RFC9000-S17-2-5-1-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetryMetadataFuzz_DiscardsPacketsThatReuseTheInitialDestinationConnectionId()
    {
        byte[][] originalDestinationConnectionIds =
        [
            [],
            [0x11],
            [0x11, 0x12, 0x13, 0x14],
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
        ];

        foreach (byte[] originalDestinationConnectionId in originalDestinationConnectionIds)
        {
            byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
                destinationConnectionId: CreateConnectionId(0x20, 4),
                sourceConnectionId: originalDestinationConnectionId,
                retryToken: CreateConnectionId(0x70, 4));

            Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
                originalDestinationConnectionId,
                retryPacket.AsSpan(0, retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength),
                retryPacket.AsSpan(retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength),
                out int integrityTagBytesWritten));
            Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, integrityTagBytesWritten);
            Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
                originalDestinationConnectionId,
                retryPacket));

            Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
                originalDestinationConnectionId,
                retryPacket,
                out _));
        }
    }

    [Fact]
    [Requirement("RFC9000-S17-2-5-1-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetryMetadataFuzz_FeedsSubsequentInitialDestinationConnectionId()
    {
        byte[] originalDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] initialSourceConnectionId =
        [
            0x21, 0x22, 0x23, 0x24,
        ];

        foreach (byte[] retrySourceConnectionId in CreateRetrySourceConnectionIds())
        {
            byte[] retryToken = CreateConnectionId(0xA0, retrySourceConnectionId.Length + 1);

            Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
                originalDestinationConnectionId,
                initialSourceConnectionId,
                retrySourceConnectionId,
                retryToken,
                out byte[] retryPacket));
            Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
                originalDestinationConnectionId,
                retryPacket,
                out QuicRetryBootstrapMetadata retryMetadata));

            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Client,
                originalDestinationConnectionId,
                out QuicInitialPacketProtection clientProtection));
            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Server,
                originalDestinationConnectionId,
                out QuicInitialPacketProtection serverProtection));

            QuicHandshakeFlowCoordinator coordinator = new(originalDestinationConnectionId, initialSourceConnectionId);
            byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x60, 20);

            Assert.True(coordinator.TryBuildProtectedInitialPacket(
                cryptoPayload,
                cryptoPayloadOffset: 0,
                retryMetadata.RetrySourceConnectionId,
                retryMetadata.RetryToken,
                clientProtection,
                out byte[] protectedPacket));
            Assert.True(coordinator.TryOpenInitialPacket(
                protectedPacket,
                serverProtection,
                out byte[] openedPacket,
                out _,
                out _));

            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                openedPacket,
                out _,
                out _,
                out ReadOnlySpan<byte> openedDestinationConnectionId,
                out ReadOnlySpan<byte> openedSourceConnectionId,
                out ReadOnlySpan<byte> versionSpecificData));
            Assert.Equal(retrySourceConnectionId, openedDestinationConnectionId.ToArray());
            Assert.Equal(initialSourceConnectionId, openedSourceConnectionId.ToArray());
            Assert.True(QuicVariableLengthInteger.TryParse(
                versionSpecificData,
                out ulong tokenLength,
                out int tokenLengthBytesConsumed));
            Assert.Equal((ulong)retryToken.Length, tokenLength);
            Assert.True(retryToken.AsSpan().SequenceEqual(
                versionSpecificData.Slice(tokenLengthBytesConsumed, retryToken.Length)));
        }
    }

    [Fact]
    [Requirement("RFC9000-S17-2-5-3-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroRttAfterRetryFuzz_UsesRetrySourceConnectionIdForSupportedLengths()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);

        foreach (byte[] retrySourceConnectionId in CreateRetrySourceConnectionIds())
        {
            QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
            Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(retrySourceConnectionId));

            Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
                QuicS17P2P3TestSupport.CreatePingPayload(),
                zeroRttMaterial,
                out byte[] protectedPacket));
            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                protectedPacket,
                out _,
                out _,
                out ReadOnlySpan<byte> destinationConnectionId,
                out _,
                out _));
            Assert.Equal(retrySourceConnectionId, destinationConnectionId.ToArray());
        }
    }

    private static byte[][] CreateRetrySourceConnectionIds()
    {
        return
        [
            [0x31],
            [0x31, 0x32, 0x33, 0x34],
            [0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58],
            [
                0x61, 0x62, 0x63, 0x64, 0x65,
                0x66, 0x67, 0x68, 0x69, 0x6A,
                0x71, 0x72, 0x73, 0x74, 0x75,
                0x76, 0x77, 0x78, 0x79, 0x7A,
            ],
        ];
    }

    private static byte[] CreateConnectionId(byte start, int length)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = (byte)(start + index);
        }

        return connectionId;
    }
}
