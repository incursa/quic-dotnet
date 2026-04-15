using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0142")]
public sealed class REQ_QUIC_CRT_0142
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
    public void BridgeStateDiscardsZeroRttMaterialWhenTheResumptionAttemptIsRejected()
    {
        QuicTransportTlsBridgeState bridge = new(QuicTlsRole.Client);
        QuicTlsPacketProtectionMaterial zeroRttMaterial = CreateZeroRttMaterial(0x41);
        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial(0x51);

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: zeroRttMaterial)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
            ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Rejected)));

        Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, bridge.ResumptionAttemptDisposition);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.False(bridge.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
        Assert.True(bridge.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.Handshake, out QuicTlsPacketProtectionMaterial remainingMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, remainingMaterial.EncryptionLevel);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRuntimeDiscardsZeroRttMaterialWhenTheResumptionAttemptIsRejected()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4_096);
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            localHandshakePrivateKey,
            detachedResumptionTicketSnapshot);

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        Assert.True(bootstrapResult.StateChanged);
        Assert.Contains(
            clientRuntime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && entry.Value.CryptoMetadata.HasValue
                && entry.Value.CryptoMetadata.Value.EncryptionLevel == QuicTlsEncryptionLevel.Initial);
        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial runtimeZeroRttMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.ZeroRtt, runtimeZeroRttMaterial.EncryptionLevel);

        QuicConnectionTransitionResult rejectionResult = clientRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: nowTicks + 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
                    ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Rejected)),
            nowTicks: nowTicks + 1);

        Assert.True(rejectionResult.StateChanged);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, clientRuntime.TlsState.ResumptionAttemptDisposition);
        Assert.True(clientRuntime.TlsState.OldKeysDiscarded);
        Assert.False(clientRuntime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
        Assert.False(clientRuntime.TlsState.HasAnyPacketProtectionMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRuntimeKeepsZeroRttMaterialWhenTheResumptionAttemptIsAccepted()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4_096);
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            localHandshakePrivateKey,
            detachedResumptionTicketSnapshot);

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        Assert.True(bootstrapResult.StateChanged);
        Assert.Contains(
            clientRuntime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && entry.Value.CryptoMetadata.HasValue
                && entry.Value.CryptoMetadata.Value.EncryptionLevel == QuicTlsEncryptionLevel.Initial);
        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial runtimeZeroRttMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.ZeroRtt, runtimeZeroRttMaterial.EncryptionLevel);

        QuicConnectionTransitionResult acceptanceResult = clientRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: nowTicks + 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
                    ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Accepted)),
            nowTicks: nowTicks + 1);

        Assert.True(acceptanceResult.StateChanged);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Accepted, clientRuntime.TlsState.ResumptionAttemptDisposition);
        Assert.False(clientRuntime.TlsState.OldKeysDiscarded);
        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
        Assert.True(clientRuntime.TlsState.HasAnyPacketProtectionMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzResumptionAttemptDispositionCleanup_RandomBranchesKeepTheZeroRttBoundaryHonest()
    {
        Random random = new(0x0142);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            bool rejected = random.Next(2) == 0;
            byte seed = (byte)random.Next(1, 256);
            QuicTransportTlsBridgeState bridge = new(QuicTlsRole.Client);

            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                PacketProtectionMaterial: CreateZeroRttMaterial(seed))));

            Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
                ResumptionAttemptDisposition: rejected
                    ? QuicTlsResumptionAttemptDisposition.Rejected
                    : QuicTlsResumptionAttemptDisposition.Accepted)));

            if (rejected)
            {
                Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, bridge.ResumptionAttemptDisposition);
                Assert.True(bridge.OldKeysDiscarded);
                Assert.False(bridge.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
            }
            else
            {
                Assert.Equal(QuicTlsResumptionAttemptDisposition.Accepted, bridge.ResumptionAttemptDisposition);
                Assert.False(bridge.OldKeysDiscarded);
                Assert.True(bridge.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
            }
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeCleanupOrReplayPromises()
    {
        string[] forbiddenFragments = ["ZeroRtt", "0Rtt", "EarlyData", "AntiReplay", "KeyUpdate", "ResumptionAttemptCleanup"];

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
}
