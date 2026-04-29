using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-CRT-0144">The managed client/runtime path MUST record the first observed 1-RTT Key Phase transition on the active short-header packet path after handshake confirmation.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-CRT-0144")]
public sealed class REQ_QUIC_CRT_0144
{
    private static readonly byte[] KeyPhaseDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly QuicConnectionPathIdentity PacketPathIdentity =
        new("203.0.113.10", RemotePort: 443);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtectedApplicationPacketCoordinatorReportsTheRequestedKeyPhaseBit()
    {
        QuicTlsPacketProtectionMaterial material = CreateOneRttPacketProtectionMaterial();
        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();

        byte[] protectedPacket = BuildProtectedApplicationPacket(coordinator, material, keyPhase: true);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        Assert.True(parsedHeader.KeyPhase);
        Assert.NotEmpty(openedPacket);
        Assert.True(payloadOffset > 0);
        Assert.True(payloadLength > 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeInstallsTheFirstObservedOneRttKeyPhaseTransition()
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(KeyPhaseDestinationConnectionId));
        Assert.NotNull(runtime.TlsState.OneRttOpenPacketProtectionMaterial);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = BuildProtectedApplicationPacket(
            CreatePacketCoordinator(),
            successorOpenMaterial,
            keyPhase: true);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzOneRttKeyPhaseBoundary_RandomizedPayloadLengthsKeepTheObservedBitHonest()
    {
        Random random = new(0x0144);
        QuicTlsPacketProtectionMaterial material = CreateOneRttPacketProtectionMaterial();

        for (int iteration = 0; iteration < 128; iteration++)
        {
            bool keyPhase = random.Next(2) == 0;
            int payloadLength = random.Next(
                1,
                QuicInitialPacketProtection.HeaderProtectionSampleOffset
                + QuicInitialPacketProtection.HeaderProtectionSampleLength
                + 16);

            byte[] payload = CreatePingPayload(payloadLength);
            QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();

            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                payload,
                material,
                keyPhase,
                out byte[] protectedPacket));

            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                material,
                out byte[] openedPacket,
                out _,
                out _,
                out bool observedKeyPhase));

            Assert.Equal(keyPhase, observedKeyPhase);
            Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
            Assert.Equal(keyPhase, parsedHeader.KeyPhase);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EstablishingClientRuntimeDoesNotInstallOneRttKeyPhaseBeforeHandshakeConfirmation()
    {
        QuicConnectionRuntime runtime = CreateEstablishingClientRuntime();
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(KeyPhaseDestinationConnectionId));
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);

        byte[] protectedPacket = BuildProtectedApplicationPacket(
            CreatePacketCoordinator(),
            CreateOneRttPacketProtectionMaterial(),
            keyPhase: true);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeKeyUpdateOrBroaderTransportPromises()
    {
        string[] forbiddenFragments = ["KeyUpdate", "0Rtt", "ZeroRtt", "EarlyData", "AntiReplay"];

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

    private static QuicConnectionRuntime CreateEstablishingClientRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client);
    }

    private static QuicHandshakeFlowCoordinator CreatePacketCoordinator()
    {
        QuicHandshakeFlowCoordinator coordinator = new(KeyPhaseDestinationConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(KeyPhaseDestinationConnectionId));
        return coordinator;
    }

    private static byte[] BuildProtectedApplicationPacket(
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase)
    {
        byte[] payload = CreatePingPayload();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(payload, material, keyPhase, out byte[] protectedPacket));
        return protectedPacket;
    }

    private static QuicTlsPacketProtectionMaterial CreateOneRttPacketProtectionMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x41, 16),
            CreateSequentialBytes(0x51, 12),
            CreateSequentialBytes(0x61, 16),
            QuicRfc9001KeyPhaseTestSupport.CreateSupportedAes128GcmPacketProtectionUsageLimits(),
            out QuicTlsPacketProtectionMaterial material));

        return material;
    }

    private static byte[] CreatePingPayload()
    {
        return CreatePingPayload(1);
    }

    private static byte[] CreatePingPayload(int length)
    {
        byte[] payload = new byte[length];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
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

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
