using System.Buffers.Binary;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0143")]
public sealed class REQ_QUIC_CRT_0143
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    private static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeStateRetainsZeroRttMaterialWhenPeerEarlyDataDispositionIsAccepted()
    {
        QuicTransportTlsBridgeState bridge = new(QuicTlsRole.Client);
        QuicTlsPacketProtectionMaterial zeroRttMaterial = CreateZeroRttMaterial(0x41);
        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial(0x51);

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
            ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Accepted)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: zeroRttMaterial)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerEarlyDataDispositionAvailable,
            PeerEarlyDataDisposition: QuicTlsEarlyDataDisposition.Accepted)));

        Assert.Equal(QuicTlsEarlyDataDisposition.Accepted, bridge.PeerEarlyDataDisposition);
        Assert.True(bridge.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
        Assert.True(bridge.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.Handshake, out QuicTlsPacketProtectionMaterial remainingMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, remainingMaterial.EncryptionLevel);
        Assert.False(bridge.OldKeysDiscarded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeStateDiscardsZeroRttMaterialWhenPeerEarlyDataDispositionIsRejected()
    {
        QuicTransportTlsBridgeState bridge = new(QuicTlsRole.Client);
        QuicTlsPacketProtectionMaterial zeroRttMaterial = CreateZeroRttMaterial(0x41);
        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial(0x51);

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
            ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Accepted)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: zeroRttMaterial)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerEarlyDataDispositionAvailable,
            PeerEarlyDataDisposition: QuicTlsEarlyDataDisposition.Rejected)));

        Assert.Equal(QuicTlsEarlyDataDisposition.Rejected, bridge.PeerEarlyDataDisposition);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.False(bridge.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
        Assert.True(bridge.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.Handshake, out QuicTlsPacketProtectionMaterial remainingMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, remainingMaterial.EncryptionLevel);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRuntimeObservesAcceptedPeerEarlyDataDispositionFromEncryptedExtensions()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateAcceptedFinishedClientRuntime(
            ticketMaxEarlyDataSize: 4_096,
            includeEarlyData: true);

        Assert.Equal(QuicTlsEarlyDataDisposition.Accepted, runtime.TlsState.PeerEarlyDataDisposition);
        Assert.False(runtime.TlsState.OldKeysDiscarded);
        Assert.True(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out QuicTlsPacketProtectionMaterial zeroRttMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.ZeroRtt, zeroRttMaterial.EncryptionLevel);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRuntimeObservesRejectedPeerEarlyDataDispositionFromEncryptedExtensions()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateAcceptedFinishedClientRuntime(
            ticketMaxEarlyDataSize: 4_096,
            includeEarlyData: false);

        Assert.Equal(QuicTlsEarlyDataDisposition.Rejected, runtime.TlsState.PeerEarlyDataDisposition);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.False(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRuntimeRejectsMalformedPeerEarlyDataDispositionTranscript()
    {
        AcceptedResumptionHandshakeContext context = CreateAcceptedResumptionHandshakeContext(includeEarlyData: true);
        long observedAtTicks = ApplyRuntimeUpdates(context.Runtime, context.BootstrapUpdates, context.ObservedAtTicks);
        observedAtTicks = ApplyRuntimeUpdates(
            context.Runtime,
            context.Driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, context.ServerHelloTranscript),
            observedAtTicks);

        byte[] malformedEncryptedExtensionsTranscript = CreateMalformedEncryptedExtensionsTranscript(context.EncryptedExtensionsTranscript);
        IReadOnlyList<QuicTlsStateUpdate> malformedUpdates = context.Driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            malformedEncryptedExtensionsTranscript);

        Assert.Single(malformedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, malformedUpdates[0].Kind);

        observedAtTicks = ApplyRuntimeUpdates(context.Runtime, malformedUpdates, observedAtTicks);
        Assert.True(context.Runtime.TlsState.IsTerminal);
        Assert.False(context.Runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRuntimeRejectsDuplicatedPeerEarlyDataDispositionTranscript()
    {
        AcceptedResumptionHandshakeContext context = CreateAcceptedResumptionHandshakeContext(includeEarlyData: true);
        long observedAtTicks = ApplyRuntimeUpdates(context.Runtime, context.BootstrapUpdates, context.ObservedAtTicks);
        observedAtTicks = ApplyRuntimeUpdates(
            context.Runtime,
            context.Driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, context.ServerHelloTranscript),
            observedAtTicks);

        byte[] duplicatedEncryptedExtensionsTranscript = CreateDuplicatedEncryptedExtensionsTranscript(context.EncryptedExtensionsTranscript);
        IReadOnlyList<QuicTlsStateUpdate> duplicatedUpdates = context.Driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            duplicatedEncryptedExtensionsTranscript);

        Assert.Single(duplicatedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, duplicatedUpdates[0].Kind);

        observedAtTicks = ApplyRuntimeUpdates(context.Runtime, duplicatedUpdates, observedAtTicks);
        Assert.True(context.Runtime.TlsState.IsTerminal);
        Assert.False(context.Runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzPeerEarlyDataDispositionBoundary_RandomizedAcceptedAndRejectedTranscriptsKeepTheZeroRttBoundaryHonest()
    {
        Random random = new(0x0143);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            bool includeEarlyData = random.Next(2) == 0;
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateAcceptedFinishedClientRuntime(
                ticketMaxEarlyDataSize: 4_096,
                includeEarlyData: includeEarlyData);

            if (includeEarlyData)
            {
                Assert.Equal(QuicTlsEarlyDataDisposition.Accepted, runtime.TlsState.PeerEarlyDataDisposition);
                Assert.False(runtime.TlsState.OldKeysDiscarded);
                Assert.True(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
            }
            else
            {
                Assert.Equal(QuicTlsEarlyDataDisposition.Rejected, runtime.TlsState.PeerEarlyDataDisposition);
                Assert.True(runtime.TlsState.OldKeysDiscarded);
                Assert.False(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
            }
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeEarlyDataAdmissionOrAntiReplayPromises()
    {
        string[] forbiddenFragments = ["ZeroRtt", "0Rtt", "EarlyData", "AntiReplay", "KeyUpdate"];

        string[] publicMembers = typeof(QuicConnection).Assembly
            .GetExportedTypes()
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(member => $"{type.FullName}.{member.Name}"))
            .Concat(
                typeof(QuicConnection).Assembly.GetExportedTypes()
                    .Select(type => type.FullName ?? type.Name))
            .ToArray();

        Assert.DoesNotContain(publicMembers, member =>
            forbiddenFragments.Any(fragment => member.Contains(fragment, StringComparison.OrdinalIgnoreCase)));
    }

    private static AcceptedResumptionHandshakeContext CreateAcceptedResumptionHandshakeContext(bool includeEarlyData)
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4_096);
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);
        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        QuicConnectionRuntime runtime = CreateClientRuntime(localHandshakePrivateKey, detachedResumptionTicketSnapshot);
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey);

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks);

        Assert.Equal(3, bootstrapUpdates.Count);

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            _) = QuicPostHandshakeTicketTestSupport.CreateAcceptedClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks,
            localHandshakePrivateKey,
            peerTransportParameters,
            includeEarlyData: includeEarlyData);

        return new AcceptedResumptionHandshakeContext(
            runtime,
            driver,
            bootstrapUpdates,
            serverHelloTranscript,
            encryptedExtensionsTranscript,
            nowTicks);
    }

    private static QuicConnectionRuntime CreateClientRuntime(
        byte[] localHandshakePrivateKey,
        QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot = null)
    {
        QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.TryConfigureInitialPacketProtection(InitialDestinationConnectionId));
        Assert.True(clientRuntime.TrySetBootstrapOutboundPath(BootstrapPath));
        Assert.True(clientRuntime.TrySetHandshakeSourceConnectionId(InitialSourceConnectionId));
        return clientRuntime;
    }

    private static byte[] CreateMalformedEncryptedExtensionsTranscript(byte[] transcript)
    {
        byte[] malformedTranscript = new byte[transcript.Length + 1];
        transcript.CopyTo(malformedTranscript, 0);

        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(transcript.AsSpan(4, 2));
        BinaryPrimitives.WriteUInt16BigEndian(malformedTranscript.AsSpan(4, 2), (ushort)(extensionsLength + 1));
        WriteUInt24(malformedTranscript.AsSpan(1, 3), transcript.Length - 4 + 1);
        BinaryPrimitives.WriteUInt16BigEndian(malformedTranscript.AsSpan(transcript.Length - 2, 2), 1);
        malformedTranscript[^1] = 0x00;
        return malformedTranscript;
    }

    private static byte[] CreateDuplicatedEncryptedExtensionsTranscript(byte[] transcript)
    {
        byte[] duplicatedTranscript = new byte[transcript.Length + 4];
        transcript.CopyTo(duplicatedTranscript, 0);

        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(transcript.AsSpan(4, 2));
        BinaryPrimitives.WriteUInt16BigEndian(duplicatedTranscript.AsSpan(4, 2), (ushort)(extensionsLength + 4));
        WriteUInt24(duplicatedTranscript.AsSpan(1, 3), transcript.Length - 4 + 4);
        duplicatedTranscript[transcript.Length] = 0x00;
        duplicatedTranscript[transcript.Length + 1] = 0x2A;
        duplicatedTranscript[transcript.Length + 2] = 0x00;
        duplicatedTranscript[transcript.Length + 3] = 0x00;
        return duplicatedTranscript;
    }

    private static long ApplyRuntimeUpdates(
        QuicConnectionRuntime runtime,
        IReadOnlyList<QuicTlsStateUpdate> updates,
        long observedAtTicks)
    {
        Assert.NotEmpty(updates);

        foreach (QuicTlsStateUpdate update in updates)
        {
            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionTlsStateUpdatedEvent(observedAtTicks, update),
                nowTicks: observedAtTicks);

            Assert.True(result.StateChanged);
            observedAtTicks++;
        }

        return observedAtTicks;
    }

    private static QuicTlsPacketProtectionMaterial CreateZeroRttMaterial(byte startValue)
    {
        return CreatePacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, startValue);
    }

    private static QuicTlsPacketProtectionMaterial CreateHandshakeMaterial(byte startValue)
    {
        return CreatePacketProtectionMaterial(QuicTlsEncryptionLevel.Handshake, startValue);
    }

    private static QuicTlsPacketProtectionMaterial CreatePacketProtectionMaterial(
        QuicTlsEncryptionLevel encryptionLevel,
        byte startValue)
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            encryptionLevel,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(startValue, 16),
            CreateSequentialBytes(unchecked((byte)(startValue + 0x10)), 12),
            CreateSequentialBytes(unchecked((byte)(startValue + 0x20)), 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        return material;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] buffer = new byte[length];
        for (int index = 0; index < buffer.Length; index++)
        {
            buffer[index] = unchecked((byte)(startValue + index));
        }

        return buffer;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }

    private sealed record AcceptedResumptionHandshakeContext(
        QuicConnectionRuntime Runtime,
        QuicTlsTransportBridgeDriver Driver,
        IReadOnlyList<QuicTlsStateUpdate> BootstrapUpdates,
        byte[] ServerHelloTranscript,
        byte[] EncryptedExtensionsTranscript,
        long ObservedAtTicks);
}
