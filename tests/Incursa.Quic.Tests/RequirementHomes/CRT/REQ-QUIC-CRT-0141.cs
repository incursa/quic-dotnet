using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0141")]
public sealed class REQ_QUIC_CRT_0141
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
    public void EligibleDormantCarrierPublishesZeroRttMaterialAndEmitsTheExpectedProtectedPacket()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4096);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.StartHandshake(
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks);

        Assert.Equal(3, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.LocalTransportParametersReady, updates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.PacketProtectionMaterialAvailable, updates[2].Kind);
        Assert.NotNull(updates[2].PacketProtectionMaterial);
        Assert.Equal(QuicTlsEncryptionLevel.ZeroRtt, updates[2].PacketProtectionMaterial!.Value.EncryptionLevel);

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            localHandshakePrivateKey,
            detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.True(clientRuntime.HasDormantEarlyDataAttemptReadiness);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        Assert.True(result.StateChanged);

        QuicConnectionSendDatagramEffect zeroRttSend = Assert.Single(GetZeroRttSendEffects(result.Effects));
        Assert.Equal(BootstrapPath, zeroRttSend.PathIdentity);
        Assert.True(IsZeroRttPacket(zeroRttSend.Datagram.Span));

        Assert.True(
            clientRuntime.TlsState.TryGetPacketProtectionMaterial(
                QuicTlsEncryptionLevel.ZeroRtt,
                out QuicTlsPacketProtectionMaterial runtimeZeroRttPacketProtectionMaterial));

        byte[] expectedPacket = BuildExpectedZeroRttPacket(
            CreateZeroRttApplicationPayload(),
            runtimeZeroRttPacketProtectionMaterial);

        Assert.Equal(expectedPacket.Length, zeroRttSend.Datagram.Length);
        Assert.True(
            expectedPacket.AsSpan().SequenceEqual(zeroRttSend.Datagram.Span),
            $"Expected={Convert.ToHexString(expectedPacket)} Actual={Convert.ToHexString(zeroRttSend.Datagram.ToArray())}");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void WithoutADormantCarrierTheBootstrapPathDoesNotEmitZeroRttMaterialOrPackets()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);
        long nowTicks = Stopwatch.Frequency;

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.StartHandshake(localTransportParameters);
        Assert.Equal(2, updates.Count);
        Assert.DoesNotContain(updates, update => update.Kind == QuicTlsUpdateKind.PacketProtectionMaterialAvailable);

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(localHandshakePrivateKey);
        Assert.False(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.False(clientRuntime.HasDormantEarlyDataAttemptReadiness);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        Assert.Empty(GetZeroRttSendEffects(result.Effects));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void WithoutTheEarlyDataPrerequisiteMaterialTheBootstrapPathDoesNotEmitZeroRttMaterialOrPackets()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.StartHandshake(
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks);

        Assert.Equal(2, updates.Count);
        Assert.DoesNotContain(updates, update => update.Kind == QuicTlsUpdateKind.PacketProtectionMaterialAvailable);

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            localHandshakePrivateKey,
            detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.False(clientRuntime.HasDormantEarlyDataAttemptReadiness);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        Assert.Empty(GetZeroRttSendEffects(result.Effects));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeZeroRttEarlyDataOrAntiReplayPromises()
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

    private static byte[] BuildExpectedZeroRttPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material)
    {
        QuicHandshakeFlowCoordinator packetCoordinator = new();
        Assert.True(packetCoordinator.TrySetInitialDestinationConnectionId(InitialDestinationConnectionId));
        Assert.True(packetCoordinator.TrySetSourceConnectionId(InitialSourceConnectionId));
        Assert.True(packetCoordinator.TryBuildProtectedZeroRttApplicationPacket(
            applicationPayload,
            material,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    private static QuicConnectionSendDatagramEffect[] GetZeroRttSendEffects(IEnumerable<QuicConnectionEffect> effects)
    {
        List<QuicConnectionSendDatagramEffect> zeroRttEffects = [];

        foreach (QuicConnectionSendDatagramEffect sendEffect in effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            if (IsZeroRttPacket(sendEffect.Datagram.Span))
            {
                zeroRttEffects.Add(sendEffect);
            }
        }

        return zeroRttEffects.ToArray();
    }

    private static bool IsZeroRttPacket(ReadOnlySpan<byte> packet)
    {
        return QuicPacketParser.TryParseLongHeader(
            packet,
            out QuicLongHeaderPacket longHeader)
            && longHeader.Version == 1
            && longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.ZeroRtt;
    }

    private static byte[] CreateZeroRttApplicationPayload()
    {
        byte[] applicationPayload =
            new byte[QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(applicationPayload, out int bytesWritten));
        Assert.True(bytesWritten > 0);
        return applicationPayload;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }
}
