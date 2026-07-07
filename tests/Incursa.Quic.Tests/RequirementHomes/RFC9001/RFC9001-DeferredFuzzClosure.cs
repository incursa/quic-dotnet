// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Tests;

public sealed class RFC9001_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9001-S3-0012")]
    [Requirement("REQ-QUIC-RFC9001-S4-0001")]
    [Requirement("REQ-QUIC-RFC9001-S4-0002")]
    [Requirement("REQ-QUIC-RFC9001-S4-0003")]
    [Requirement("REQ-QUIC-RFC9001-S4-0004")]
    [Requirement("REQ-QUIC-RFC9001-S4-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFramesRoundTripInsideProtectedHandshakePacketsAcrossOffsets()
    {
        QuicTlsPacketProtectionMaterial material = CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            seed: 0x11);
        QuicTlsPacketProtectionMaterial wrongMaterial = CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            seed: 0x51);
        QuicHandshakeFlowCoordinator coordinator = CreateCoordinator();

        foreach ((ulong offset, byte[] data) in CryptoHandshakeCases())
        {
            Assert.True(coordinator.TryBuildProtectedHandshakePacket(
                data,
                offset,
                material,
                out byte[] protectedPacket));

            Assert.False(coordinator.TryOpenHandshakePacket(
                protectedPacket,
                wrongMaterial,
                out _,
                out _,
                out _));

            Assert.True(coordinator.TryOpenHandshakePacket(
                protectedPacket,
                material,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));
            Assert.True(QuicFrameCodec.TryParseCryptoFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out QuicCryptoFrame parsed,
                out int bytesConsumed));
            Assert.InRange(bytesConsumed, 1, payloadLength);
            Assert.Equal(offset, parsed.Offset);
            Assert.Equal(data, parsed.CryptoData.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-S4-0006")]
    [Requirement("REQ-QUIC-RFC9001-S4-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeChunksStayBoundToTheOriginalEncryptionLevelKeys()
    {
        QuicTlsPacketProtectionMaterial firstHandshakeMaterial = CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            seed: 0x21);
        QuicTlsPacketProtectionMaterial nextHandshakeMaterial = CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            seed: 0x61);
        QuicTlsPacketProtectionMaterial oneRttMaterial = CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            seed: 0x31);
        QuicHandshakeFlowCoordinator coordinator = CreateCoordinator();

        foreach ((ulong offset, byte[] data) in CryptoHandshakeCases())
        {
            Assert.True(coordinator.TryBuildProtectedHandshakePacket(
                data,
                offset,
                firstHandshakeMaterial,
                out ulong firstPacketNumber,
                out byte[] originalProtectedPacket));
            Assert.True(coordinator.TryBuildProtectedHandshakePacketForRetransmission(
                data,
                offset,
                destinationConnectionId: [0x83, 0x94, 0xC8, 0xF0],
                sourceConnectionId: [0x33, 0x44, 0x55, 0x66],
                firstHandshakeMaterial,
                out ulong retransmittedPacketNumber,
                out byte[] retransmittedProtectedPacket));

            Assert.NotEqual(firstPacketNumber, retransmittedPacketNumber);
            Assert.True(coordinator.TryOpenHandshakePacket(
                originalProtectedPacket,
                firstHandshakeMaterial,
                out _,
                out _,
                out _));
            Assert.True(coordinator.TryOpenHandshakePacket(
                retransmittedProtectedPacket,
                firstHandshakeMaterial,
                out _,
                out _,
                out _));
            Assert.False(coordinator.TryOpenHandshakePacket(
                retransmittedProtectedPacket,
                nextHandshakeMaterial,
                out _,
                out _,
                out _));
            Assert.False(coordinator.TryOpenHandshakePacket(
                retransmittedProtectedPacket,
                oneRttMaterial,
                out _,
                out _,
                out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-S6-0002")]
    [Requirement("REQ-QUIC-RFC9001-S6-0003")]
    [Requirement("REQ-QUIC-RFC9001-S6-0004")]
    [Requirement("REQ-QUIC-RFC9001-S6P1-0001")]
    [Requirement("REQ-QUIC-RFC9001-S6P1-0002")]
    [Requirement("REQ-QUIC-RFC9001-S6P1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_KeyPhaseTogglesAndSuccessorWriteKeysProtectSubsequentPackets()
    {
        foreach (Func<QuicConnectionRuntime> runtimeFactory in KeyUpdateRuntimeFactories())
        {
            using QuicConnectionRuntime runtime = runtimeFactory();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

            QuicTlsPacketProtectionMaterial initialProtectMaterial =
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
            Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseBit);

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
                runtime,
                out _,
                out QuicTlsPacketProtectionMaterial successorProtectMaterial));
            Assert.True(initialProtectMaterial.HeaderProtectionKey.SequenceEqual(successorProtectMaterial.HeaderProtectionKey));
            Assert.False(initialProtectMaterial.AeadKey.SequenceEqual(successorProtectMaterial.AeadKey));
            Assert.False(initialProtectMaterial.AeadIv.SequenceEqual(successorProtectMaterial.AeadIv));

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
            Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseBit);
            Assert.True(successorProtectMaterial.Matches(
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));

            QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
            foreach (byte[] payload in ApplicationPayloadCases())
            {
                Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                    payload,
                    runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                    keyPhase: true,
                    out byte[] protectedPacket));
                Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
                    protectedPacket,
                    initialProtectMaterial,
                    out _,
                    out _,
                    out _,
                    out _));
                Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                    protectedPacket,
                    runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                    out byte[] openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out bool observedKeyPhase));
                Assert.True(observedKeyPhase);
                Assert.True(payloadLength >= payload.Length);
                Assert.Equal(payload, openedPacket.AsSpan(payloadOffset, payload.Length).ToArray());
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-S6P1-0007")]
    [Requirement("REQ-QUIC-RFC9001-S6P1-0008")]
    [Requirement("REQ-QUIC-RFC9001-S6P5-0007")]
    [Requirement("RFC9001-S6-1-P7-S1-R01")]
    [Requirement("RFC9001-S6-P1-S1-R01")]
    [Requirement("RFC9001-S6-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LocalKeyUpdatesRetainOldKeysAndAdvancePastTheWireKeyPhaseBit()
    {
        uint[] targetPhases = [1, 2, 3, 4, 5, 32, 33];
        foreach (uint targetPhase in targetPhases)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

            if (targetPhase == 1)
            {
                Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
            }
            else
            {
                QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseWithPreviousRetained(
                    runtime,
                    targetPhase);
            }

            Assert.Equal(targetPhase, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.Equal((targetPhase & 1U) == 1U, runtime.TlsState.CurrentOneRttKeyPhaseBit);
            Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
            Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);

            QuicConnectionTransitionResult currentPhasePacketResult =
                QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                    runtime,
                    observedAtTicks: Stopwatch.Frequency * ((long)targetPhase + 10L));
            Assert.True(currentPhasePacketResult.StateChanged);
            Assert.Equal((ulong)(targetPhase - 1U), runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
            Assert.True(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.HasValue);
        }
    }

    [Fact]
    [Requirement("RFC9001-S6-P3-S1-R01")]
    [Requirement("RFC9001-S6-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ChangedPeerKeyPhaseBitInstallsNextReceiveKeys()
    {
        foreach (byte[] payload in ApplicationPayloadCases())
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
                runtime,
                out QuicTlsPacketProtectionMaterial successorOpenMaterial,
                out _));

            QuicConnectionTransitionResult updateResult =
                QuicRfc9001RepeatedKeyUpdateTestSupport.ReceivePeerUpdatePacket(
                    runtime,
                    successorOpenMaterial,
                    keyPhase: true,
                    observedAtTicks: Stopwatch.Frequency,
                    payload);

            Assert.True(updateResult.StateChanged);
            Assert.Equal(1UL, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseBit);
            Assert.True(successorOpenMaterial.Matches(
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-S6P1-0008")]
    [Requirement("REQ-QUIC-RFC9001-S6P5-0007")]
    [Requirement("REQ-QUIC-RFC9001-S6-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RepeatedPeerAndLocalKeyUpdatesPreserveEpochStateBeyondSingleBitPhases()
    {
        foreach (uint targetPhase in new uint[] { 2, 3, 4, 5, 16, 33 })
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

            ulong nextNotBeforeMicros =
                QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareCurrentPhaseWithOldDiscardedAndAcknowledged(
                    runtime,
                    targetPhase);

            Assert.Equal(targetPhase, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.Equal((targetPhase & 1U) == 1U, runtime.TlsState.CurrentOneRttKeyPhaseBit);
            Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
            Assert.True(nextNotBeforeMicros > 0);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-S8-0001")]
    [Requirement("REQ-QUIC-RFC9001-S8-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TransportParametersAreCarriedInAuthenticatedEncryptedExtensionsTranscripts()
    {
        foreach (QuicTransportParameters parameters in TransportParameterCases())
        {
            byte[] encoded = new byte[512];
            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Server,
                encoded,
                out int bytesWritten));

            byte[] encryptedExtensions = new byte[1024];
            Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
                parameters,
                QuicTransportParameterRole.Server,
                encryptedExtensions,
                out int transcriptBytesWritten));

            Assert.Equal((byte)QuicTlsHandshakeMessageType.EncryptedExtensions, encryptedExtensions[0]);
            AssertContainsSequence(
                encryptedExtensions.AsSpan(0, transcriptBytesWritten),
                encoded.AsSpan(0, bytesWritten));
            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                encoded.AsSpan(0, bytesWritten),
                QuicTransportParameterRole.Client,
                out QuicTransportParameters parsedParameters));
            Assert.Equal(parameters.MaxIdleTimeout, parsedParameters.MaxIdleTimeout);
            Assert.Equal(parameters.DisableActiveMigration, parsedParameters.DisableActiveMigration);

            QuicTransportTlsBridgeState bridge = new();
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.LocalTransportParametersReady,
                TransportParameters: new QuicTransportParameters())));
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.TranscriptProgressed,
                HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                HandshakeMessageLength: 48,
                SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)));
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.TranscriptProgressed,
                TransportParameters: parsedParameters,
                HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
                HandshakeMessageLength: checked((uint)transcriptBytesWritten),
                TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.TranscriptProgressed,
                HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
                HandshakeMessageLength: 48,
                TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.PeerCertificateVerifyVerified)));
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.PeerCertificatePolicyAccepted)));
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.TranscriptProgressed,
                HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                HandshakeMessageLength: 48,
                TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.PeerFinishedVerified)));
            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.PeerTransportParametersCommitted,
                TransportParameters: parsedParameters)));
            Assert.True(bridge.PeerTransportParametersCommitted);
            Assert.NotSame(parsedParameters, bridge.PeerTransportParameters);
            Assert.Equal(parameters.MaxIdleTimeout, bridge.PeerTransportParameters!.MaxIdleTimeout);
        }
    }

    private static IEnumerable<(ulong Offset, byte[] Data)> CryptoHandshakeCases()
    {
        yield return (0, [0x01]);
        yield return (7, [0x02, 0x03, 0x04, 0x05]);
        yield return (63, Enumerable.Range(0, 32).Select(value => (byte)(0x80 + value)).ToArray());
    }

    private static IEnumerable<byte[]> ApplicationPayloadCases()
    {
        yield return QuicRfc9001KeyPhaseTestSupport.CreatePingPayload();

        byte[] streamPayload = new byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            0x0A,
            0,
            0,
            [0x44, 0x55, 0x66],
            streamPayload,
            out int streamBytesWritten));
        yield return streamPayload[..streamBytesWritten];

        byte[] ackPayload = new byte[32];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(
            new QuicAckFrame
            {
                FrameType = 0x02,
                LargestAcknowledged = 1,
                AckDelay = 0,
                FirstAckRange = 0,
                AdditionalRanges = [],
            },
            ackPayload,
            out int ackBytesWritten));
        yield return ackPayload[..ackBytesWritten];
    }

    private static IEnumerable<Func<QuicConnectionRuntime>> KeyUpdateRuntimeFactories()
    {
        yield return QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime;
        yield return () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
    }

    private static IEnumerable<QuicTransportParameters> TransportParameterCases()
    {
        yield return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            DisableActiveMigration = false,
            InitialSourceConnectionId = [0x01, 0x02],
            ActiveConnectionIdLimit = 2,
        };
        yield return new QuicTransportParameters
        {
            MaxIdleTimeout = 90,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC, 0xDD],
            ActiveConnectionIdLimit = 8,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address =
                [
                    0x20, 0x01, 0x0D, 0xB8,
                    0x00, 0x01, 0x00, 0x02,
                    0x00, 0x03, 0x00, 0x04,
                    0x00, 0x05, 0x00, 0x06,
                ],
                IPv6Port = 8443,
                ConnectionId = [0x10, 0x11, 0x12],
                StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x20 + value)).ToArray(),
            },
        };
    }

    private static QuicHandshakeFlowCoordinator CreateCoordinator()
    {
        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TrySetDestinationConnectionId([0x83, 0x94, 0xC8, 0xF0]));
        Assert.True(coordinator.TrySetSourceConnectionId([0x33, 0x44, 0x55, 0x66]));
        return coordinator;
    }

    private static void AssertContainsSequence(ReadOnlySpan<byte> source, ReadOnlySpan<byte> expected)
    {
        for (int index = 0; index <= source.Length - expected.Length; index++)
        {
            if (source.Slice(index, expected.Length).SequenceEqual(expected))
            {
                return;
            }
        }

        Assert.Fail("Expected byte sequence was not present.");
    }

    private static QuicTlsPacketProtectionMaterial CreatePacketProtectionMaterial(
        QuicTlsEncryptionLevel encryptionLevel,
        byte seed)
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            encryptionLevel,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(seed, 16),
            CreateSequentialBytes((byte)(seed + 0x20), 12),
            CreateSequentialBytes((byte)(seed + 0x40), 16),
            QuicRfc9001KeyPhaseTestSupport.CreateSupportedAes128GcmPacketProtectionUsageLimits(),
            out QuicTlsPacketProtectionMaterial material));

        return material;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }
}
