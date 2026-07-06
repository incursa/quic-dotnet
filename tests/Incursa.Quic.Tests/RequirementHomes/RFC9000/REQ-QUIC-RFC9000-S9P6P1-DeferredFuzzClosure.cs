// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S9P6P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientSelectsPreferredAddressAndStartsValidationAfterHandshakeConfirmation()
    {
        foreach (bool useIpv6 in new[]
        {
            false,
            true,
        })
        {
            QuicConnectionPathIdentity originalPath = useIpv6
                ? QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path
                : QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path;
            using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
                originalPath,
                QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
            QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6);

            QuicConnectionTransitionResult result = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
                runtime,
                observedAtTicks: useIpv6 ? 24 : 20);

            Assert.True(result.StateChanged);
            Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
            QuicS9P6P1PreferredAddressTestSupport.AssertCandidatePathPendingValidation(runtime, preferredPath);
            QuicS9P6P1PreferredAddressTestSupport.AssertPathChallengeSent(runtime, result, preferredPath);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ValidatedPreferredAddressBecomesFuturePacketPathAndOriginalAddressIsDiscontinued()
    {
        foreach (bool useIpv6 in new[] { false, true })
        {
            QuicConnectionPathIdentity originalPath = useIpv6
                ? QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path
                : QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path;
            using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
                originalPath,
                QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
            QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6);

            QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
            QuicConnectionTransitionResult validationResult = QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
                runtime,
                preferredPath,
                observedAtTicks: useIpv6 ? 34 : 30);

            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == preferredPath
                && !promote.RestoreSavedState);
            Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(
                QuicS9P6P1PreferredAddressTestSupport.PreferredConnectionId));
            AssertProtectedApplicationPacketUsesCurrentDestinationConnectionId(runtime);

            QuicConnectionTransitionResult oldAddressResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: useIpv6 ? 44 : 40,
                    originalPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: useIpv6 ? 44 : 40);

            Assert.False(oldAddressResult.StateChanged);
            Assert.Equal(preferredPath, runtime.ActivePath.Value.Identity);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerConveysPreferredAddressTransportParameterInEncryptedExtensions()
    {
        foreach ((byte seed, ushort ipv4Port, ushort ipv6Port, int connectionIdLength) in new[]
        {
            ((byte)0x20, (ushort)443, (ushort)8443, 4),
            ((byte)0x40, (ushort)9444, (ushort)9554, 8),
            ((byte)0x60, (ushort)65535, (ushort)1, 20),
        })
        {
            QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                preferredConnectionId: CreateBytes(seed, connectionIdLength),
                preferredIpv4Address: [198, 51, 100, seed],
                preferredIpv4Port: ipv4Port,
                preferredIpv6Address: CreateIpv6Address(seed),
                preferredIpv6Port: ipv6Port,
                statelessResetToken: CreateBytes((byte)(seed + 0x10), 16));
            QuicTransportParameters parameters = new()
            {
                InitialSourceConnectionId = QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId,
                PreferredAddress = preferredAddress,
            };
            byte[] transcript = new byte[512];

            Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
                parameters,
                QuicTransportParameterRole.Server,
                transcript,
                out int bytesWritten));

            ReadOnlySpan<byte> transportParameters = GetOnlyTransportParametersExtension(transcript.AsSpan(0, bytesWritten));
            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                transportParameters,
                QuicTransportParameterRole.Client,
                out QuicTransportParameters parsed));
            Assert.NotNull(parsed.PreferredAddress);
            AssertPreferredAddressEqual(preferredAddress, parsed.PreferredAddress!);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientUsesUnusedPreferredOrNewConnectionIdForPreferredAddressMigration()
    {
        foreach ((bool installNewConnectionId, int connectionIdLength) in new[]
        {
            (false, 4),
            (false, 8),
            (true, 12),
            (true, 20),
        })
        {
            byte[] preferredConnectionId = CreateBytes(0x70, connectionIdLength);
            byte[] newConnectionId = CreateBytes(0x90, connectionIdLength);
            byte[] resetToken = CreateBytes(0xA0, 16);
            using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateConfirmedClientRuntime(
                QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
                CreatePreferredAddress(preferredConnectionId, resetToken));
            QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20,
                    preferredPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20);

            byte[] expectedConnectionId = preferredConnectionId;
            if (installNewConnectionId)
            {
                ReceiveNewConnectionIdFrame(
                    runtime,
                    sequenceNumber: 2,
                    retirePriorTo: 0,
                    connectionId: newConnectionId,
                    statelessResetToken: resetToken,
                    observedAtTicks: 24);
                expectedConnectionId = newConnectionId;
            }

            QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
                runtime,
                preferredPath,
                observedAtTicks: 30);

            Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(expectedConnectionId));
            AssertProtectedApplicationPacketUsesCurrentDestinationConnectionId(runtime);
        }
    }

    private static void AssertProtectedApplicationPacketUsesCurrentDestinationConnectionId(QuicConnectionRuntime runtime)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(
            runtime.CurrentPeerDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId);
        byte[] payload = [0x51, 0x52, 0x53, 0x54];

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            out byte[] protectedPacket));

        Assert.True(protectedPacket.Length > 1 + runtime.CurrentPeerDestinationConnectionId.Length);
        Assert.True(protectedPacket.AsSpan(1, runtime.CurrentPeerDestinationConnectionId.Length).SequenceEqual(
            runtime.CurrentPeerDestinationConnectionId.Span));
    }

    private static QuicPreferredAddress CreatePreferredAddress(byte[] connectionId, byte[] statelessResetToken)
    {
        return new QuicPreferredAddress
        {
            IPv4Address = QuicS9P6P1PreferredAddressTestSupport.PreferredIpv4Address.ToArray(),
            IPv4Port = 9444,
            IPv6Address = QuicS9P6P1PreferredAddressTestSupport.PreferredIpv6Address.ToArray(),
            IPv6Port = 9554,
            ConnectionId = connectionId.ToArray(),
            StatelessResetToken = statelessResetToken.ToArray(),
        };
    }

    private static QuicConnectionTransitionResult ReceiveNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            statelessResetToken));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(
            runtime.CurrentPeerDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    private static ReadOnlySpan<byte> GetOnlyTransportParametersExtension(ReadOnlySpan<byte> encryptedExtensions)
    {
        Assert.True(encryptedExtensions.Length >= 10);
        int bodyLength = ReadUInt24(encryptedExtensions.Slice(1, 3));
        Assert.Equal(encryptedExtensions.Length - 4, bodyLength);

        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(encryptedExtensions.Slice(4, 2));
        Assert.Equal(encryptedExtensions.Length - 6, extensionsLength);

        ushort extensionType = BinaryPrimitives.ReadUInt16BigEndian(encryptedExtensions.Slice(6, 2));
        Assert.Equal(QuicTransportParametersCodec.QuicTransportParametersExtensionType, extensionType);

        ushort extensionLength = BinaryPrimitives.ReadUInt16BigEndian(encryptedExtensions.Slice(8, 2));
        Assert.Equal(encryptedExtensions.Length - 10, extensionLength);

        return encryptedExtensions.Slice(10, extensionLength);
    }

    private static int ReadUInt24(ReadOnlySpan<byte> source)
    {
        return (source[0] << 16) | (source[1] << 8) | source[2];
    }

    private static void AssertPreferredAddressEqual(QuicPreferredAddress expected, QuicPreferredAddress actual)
    {
        Assert.Equal(expected.IPv4Address, actual.IPv4Address);
        Assert.Equal(expected.IPv4Port, actual.IPv4Port);
        Assert.Equal(expected.IPv6Address, actual.IPv6Address);
        Assert.Equal(expected.IPv6Port, actual.IPv6Port);
        Assert.Equal(expected.ConnectionId, actual.ConnectionId);
        Assert.Equal(expected.StatelessResetToken, actual.StatelessResetToken);
    }

    private static byte[] CreateBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(seed + index);
        }

        return bytes;
    }

    private static byte[] CreateIpv6Address(byte seed)
    {
        byte[] address = new byte[16];
        address[0] = 0x20;
        address[1] = 0x01;
        address[2] = 0x0D;
        address[3] = 0xB8;
        address[^1] = seed;
        return address;
    }
}
