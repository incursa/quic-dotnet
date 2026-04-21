using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-CRT-0145">In the client role, after handshake confirmation and on the active 1-RTT short-header packet path, the library MUST retain the current 1-RTT application traffic secret material long enough to derive a successor 1-RTT open/protect packet-protection pair when the peer Key Phase bit first transitions from 0 to 1. On that first observed 0->1 transition, the runtime MUST derive successor 1-RTT AEAD key/IV material from the retained application traffic secret material, MUST retain the currently installed 1-RTT header-protection keys for that first supported successor pair, MUST install the successor open/protect material into the existing bridge-state fields, MUST update `KeyUpdateInstalled` and `CurrentOneRttKeyPhase` to 1, and MUST cause subsequently protected outbound 1-RTT packets to use the installed phase-1 material and set the Key Phase bit accordingly. Before handshake confirmation, the establishing runtime MUST remain unchanged. The slice MUST remain client-role only, MUST remain managed client/runtime only, and MUST remain closed to repeated successor derivation, a general RFC 9001 key-update engine, TLS KeyUpdate support, transfer, retry, public API widening, and any public key-update promise.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-CRT-0145")]
public sealed class REQ_QUIC_CRT_0145
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
    public void ActiveClientRuntimeInstallsSuccessorOneRttPacketProtectionMaterialOnTheFirstObservedTransition()
    {
        using QuicConnectionRuntime runtime = CreateFinishedClientRuntime();
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(KeyPhaseDestinationConnectionId));

        QuicTlsPacketProtectionMaterial priorProtectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
        QuicConnectionTransitionResult result = InstallFirstObservedKeyPhaseTransition(runtime);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.False(priorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeInstallsSuccessorMaterialWhenTheFirstObservedPhaseOnePacketArrivesAfterLongPhaseZeroHistory()
    {
        using QuicConnectionRuntime runtime = CreateFinishedClientRuntime();
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(KeyPhaseDestinationConnectionId));

        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial currentOpenMaterial = runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        for (int packetIndex = 0; packetIndex < 100; packetIndex++)
        {
            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                CreatePingPayload(),
                currentOpenMaterial,
                keyPhase: false,
                out byte[] phaseZeroPacket));

            QuicConnectionTransitionResult phaseZeroResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: packetIndex + 1,
                    PacketPathIdentity,
                    phaseZeroPacket),
                nowTicks: packetIndex + 1);

            Assert.True(phaseZeroResult.StateChanged);
        }

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            CreatePingPayload(),
            successorOpenMaterial,
            keyPhase: true,
            out byte[] phaseOnePacket));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 101,
                PacketPathIdentity,
                phaseOnePacket),
            nowTicks: 101);

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EstablishingClientRuntimeDoesNotInstallSuccessorMaterialBeforeHandshakeConfirmation()
    {
        using QuicConnectionRuntime runtime = CreateEstablishingClientRuntime();
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(KeyPhaseDestinationConnectionId));

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
    public void ActiveClientRuntimeIgnoresASecondObservedPhaseOneTransition()
    {
        using QuicConnectionRuntime runtime = CreateInstalledClientRuntime();
        QuicTlsPacketProtectionMaterial previousProtectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        byte[] duplicatePacket = BuildProtectedApplicationPacket(
            CreatePacketCoordinator(),
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            keyPhase: true);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                PacketPathIdentity,
                duplicatePacket),
            nowTicks: 2);

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(previousProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DirectBridgeDriverInstallsSuccessorMaterialOnlyOnce()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();

        Assert.True(driver.TryInstallOneRttKeyUpdate());
        QuicTlsPacketProtectionMaterial installedOpenMaterial = driver.State.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial installedProtectMaterial = driver.State.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.False(driver.TryInstallOneRttKeyUpdate());
        Assert.True(driver.State.KeyUpdateInstalled);
        Assert.Equal(1U, driver.State.CurrentOneRttKeyPhase);
        Assert.True(installedOpenMaterial.Matches(driver.State.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(installedProtectMaterial.Matches(driver.State.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ActiveClientRuntimeUsesTheInstalledPhaseOneBitForSubsequentOutboundStreamPackets()
    {
        using QuicConnectionRuntime runtime = CreateInstalledClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream outboundStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(PacketPathIdentity, sendEffect.PathIdentity);

        Assert.Contains(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.AckOnlyPacket);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.Retransmittable);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, trackedPacket.Key.PacketNumberSpace);
        Assert.Equal(1UL, trackedPacket.Key.PacketNumber);
        Assert.Equal((ulong)sendEffect.Datagram.Length, trackedPacket.Value.PayloadBytes);

        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            out byte[] openedPacket,
            out _,
            out _,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        Assert.True(parsedHeader.KeyPhase);

        await outboundStream.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzSuccessorKeyPhaseBoundary_RandomizedPayloadLengthsKeepTheInstalledBitHonest()
    {
        using QuicConnectionRuntime runtime = CreateInstalledClientRuntime();
        QuicTlsPacketProtectionMaterial protectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
        Random random = new(0x0145);

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
                protectMaterial,
                keyPhase,
                out byte[] protectedPacket));

            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                protectMaterial,
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

    private static QuicConnectionRuntime CreateInstalledClientRuntime()
    {
        QuicConnectionRuntime runtime = CreateFinishedClientRuntime();
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(KeyPhaseDestinationConnectionId));

        QuicConnectionTransitionResult result = InstallFirstObservedKeyPhaseTransition(runtime);
        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        return runtime;
    }

    private static QuicConnectionTransitionResult InstallFirstObservedKeyPhaseTransition(QuicConnectionRuntime runtime)
    {
        Assert.NotNull(runtime.TlsState.OneRttOpenPacketProtectionMaterial);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.CreateSuccessorPhaseOneApplicationPacket(successorOpenMaterial);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);
    }

    private static QuicConnectionRuntime CreateFinishedClientRuntime()
    {
        return QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
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
            new QuicAeadUsageLimits(64, 128),
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
