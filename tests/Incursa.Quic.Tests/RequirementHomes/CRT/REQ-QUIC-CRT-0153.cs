using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0153")]
public sealed class REQ_QUIC_CRT_0153
{
    private const int HandshakeHeaderLength = 4;
    private const int UInt16Length = sizeof(ushort);
    private const int UInt24Length = 3;
    private const ushort EarlyDataExtensionType = 0x002a;
    private const uint QuicEarlyDataMaxEarlyDataSizeSentinel = uint.MaxValue;

    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    private static readonly byte[] PacketSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    private static readonly QuicConnectionPathIdentity PacketPathIdentity =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EnabledServerEarlyDataAdvertisesNewSessionTicketExtensionAndStoresRememberedParameters()
    {
        QuicServerResumptionTicketStore ticketStore = new();
        _ = QuicPostHandshakeTicketTestSupport.CreateFinishedServerDriver(
            enableServerResumptionTickets: true,
            out IReadOnlyList<QuicTlsStateUpdate> finishedUpdates,
            ticketStore,
            enableServerEarlyData: true);

        byte[] newSessionTicket = GetCryptoData(
            finishedUpdates,
            QuicTlsEncryptionLevel.OneRtt,
            QuicTlsHandshakeMessageType.NewSessionTicket);
        Assert.True(TryParseNewSessionTicketEarlyData(newSessionTicket, out IssuedTicket issuedTicket, out uint maxEarlyDataSize));
        Assert.Equal(QuicEarlyDataMaxEarlyDataSizeSentinel, maxEarlyDataSize);

        Assert.True(ticketStore.TryGetLiveTicket(issuedTicket.TicketBytes, out QuicServerResumptionTicketRecord storedTicket));
        Assert.NotNull(storedTicket.ZeroRttTransportParameters);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S5P3-0002")]
    public void ServerAcceptsOfferedEarlyDataAfterValidatedSameListenerTicketAndPublishesZeroRttOpenMaterial()
    {
        QuicServerResumptionTicketStore ticketStore = new();
        QuicDetachedResumptionTicketSnapshot ticketSnapshot = CreateStoredEarlyDataTicketSnapshot(ticketStore);
        (byte[] clientHello, QuicTlsPacketProtectionMaterial clientZeroRttMaterial) =
            CreateEarlyDataClientHello(ticketSnapshot);
        QuicTlsTransportBridgeDriver serverDriver = CreateServerDriver(ticketStore, enableServerEarlyData: true);

        IReadOnlyList<QuicTlsStateUpdate> serverUpdates = serverDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            clientHello);

        QuicResumptionClientHelloTestSupport.ParsedClientHello parsedClientHello =
            QuicResumptionClientHelloTestSupport.ParseClientHello(clientHello);
        Assert.True(parsedClientHello.HasEarlyData);
        Assert.True(parsedClientHello.PreSharedKeyIsLastExtension);
        Assert.True(QuicResumptionClientHelloTestSupport.VerifyBinder(clientHello, ticketSnapshot));
        Assert.Contains(
            serverUpdates,
            update => update.Kind == QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable
                && update.ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Accepted);

        QuicTlsPacketProtectionMaterial serverZeroRttOpenMaterial =
            Assert.Single(serverUpdates, IsZeroRttMaterialUpdate).PacketProtectionMaterial!.Value;
        Assert.True(serverZeroRttOpenMaterial.Matches(clientZeroRttMaterial));

        byte[] encryptedExtensions = GetCryptoData(
            serverUpdates,
            QuicTlsEncryptionLevel.Handshake,
            QuicTlsHandshakeMessageType.EncryptedExtensions);
        Assert.True(HandshakeMessageHasZeroLengthExtension(encryptedExtensions, EarlyDataExtensionType));
        Assert.True(serverDriver.State.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DisabledServerEarlyDataAndReplayKeepZeroRttOpenMaterialAndEncryptedExtensionsClosed()
    {
        QuicServerResumptionTicketStore disabledTicketStore = new();
        QuicDetachedResumptionTicketSnapshot disabledSnapshot = CreateStoredEarlyDataTicketSnapshot(disabledTicketStore);
        (byte[] disabledClientHello, _) = CreateEarlyDataClientHello(disabledSnapshot);
        QuicTlsTransportBridgeDriver disabledServerDriver = CreateServerDriver(
            disabledTicketStore,
            enableServerEarlyData: false);

        IReadOnlyList<QuicTlsStateUpdate> disabledUpdates = disabledServerDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            disabledClientHello);

        Assert.DoesNotContain(disabledUpdates, IsZeroRttMaterialUpdate);
        Assert.False(HandshakeMessageHasZeroLengthExtension(
            GetCryptoData(disabledUpdates, QuicTlsEncryptionLevel.Handshake, QuicTlsHandshakeMessageType.EncryptedExtensions),
            EarlyDataExtensionType));

        QuicServerResumptionTicketStore replayTicketStore = new();
        QuicDetachedResumptionTicketSnapshot replaySnapshot = CreateStoredEarlyDataTicketSnapshot(replayTicketStore);
        (byte[] replayClientHello, _) = CreateEarlyDataClientHello(replaySnapshot);

        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = CreateServerDriver(
                replayTicketStore,
                enableServerEarlyData: true)
            .ProcessCryptoFrame(QuicTlsEncryptionLevel.Initial, replayClientHello);
        Assert.Contains(firstUpdates, IsZeroRttMaterialUpdate);

        IReadOnlyList<QuicTlsStateUpdate> replayUpdates = CreateServerDriver(
                replayTicketStore,
                enableServerEarlyData: true)
            .ProcessCryptoFrame(QuicTlsEncryptionLevel.Initial, replayClientHello);
        Assert.DoesNotContain(replayUpdates, IsZeroRttMaterialUpdate);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRuntimeOpensAdmittedZeroRttStreamPayload()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial =
            QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt);
        using QuicConnectionRuntime runtime = CreateServerRuntimeWithZeroRttOpenMaterial(zeroRttMaterial);
        byte[] streamPayload = [0x41, 0x42, 0x43, 0x44];
        byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
            QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask,
            streamId: 0,
            streamPayload);
        byte[] protectedPacket = BuildProtectedZeroRttPacket(streamFrame, zeroRttMaterial);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 2, PacketPathIdentity, protectedPacket),
            nowTicks: 2);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal((ulong)streamPayload.Length, snapshot.UniqueBytesReceived);
        Assert.Equal(streamPayload.Length, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRuntimeRejectsForbiddenZeroRttAckFrameWithoutDeliveringStreamData()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial =
            QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt);
        using QuicConnectionRuntime runtime = CreateServerRuntimeWithZeroRttOpenMaterial(zeroRttMaterial);
        byte[] protectedPacket = BuildProtectedZeroRttPacket(
            QuicS17P2P3TestSupport.CreateAckResponsePayload(),
            zeroRttMaterial);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 2, PacketPathIdentity, protectedPacket),
            nowTicks: 2);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(0x02UL, runtime.TerminalState?.Close.TriggeringFrameType);
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzServerRuntimeOpensAuthenticatedZeroRttStreamPayloads()
    {
        Random random = new(0x0153);
        QuicTlsPacketProtectionMaterial zeroRttMaterial =
            QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt);

        for (int iteration = 0; iteration < 24; iteration++)
        {
            byte[] streamPayload = new byte[1 + (iteration % 6)];
            random.NextBytes(streamPayload);
            using QuicConnectionRuntime runtime = CreateServerRuntimeWithZeroRttOpenMaterial(zeroRttMaterial);
            byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
                QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask,
                streamId: 0,
                streamPayload);
            byte[] protectedPacket = BuildProtectedZeroRttPacket(streamFrame, zeroRttMaterial);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 2 + iteration, PacketPathIdentity, protectedPacket),
                nowTicks: 2 + iteration);

            Assert.True(result.StateChanged);
            Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal((ulong)streamPayload.Length, snapshot.UniqueBytesReceived);
        }
    }

    private static QuicConnectionRuntime CreateServerRuntimeWithZeroRttOpenMaterial(
        QuicTlsPacketProtectionMaterial zeroRttMaterial)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionReceiveLimit: 256,
                incomingBidirectionalStreamLimit: 4,
                localBidirectionalReceiveLimit: 64,
                peerBidirectionalReceiveLimit: 64),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TrySetHandshakeSourceConnectionId(PacketSourceConnectionId));
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(PacketConnectionId));
        Assert.True(InitializeRuntimeActivePath(runtime, PacketPathIdentity, 1200, observedAtTicks: 0));
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: zeroRttMaterial)),
            nowTicks: 1).StateChanged);
        Assert.True(runtime.IsEarlyDataAdmissionOpen);
        return runtime;
    }

    private static QuicTlsTransportBridgeDriver CreateServerDriver(
        QuicServerResumptionTicketStore ticketStore,
        bool enableServerEarlyData)
    {
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        using ECDsa localLeafCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localLeafCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        QuicTlsTransportBridgeDriver serverDriver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: CreateScalar(0x22),
            localServerLeafCertificateDer: QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localLeafCertificateKey),
            localServerLeafSigningPrivateKey: localSigningPrivateKey,
            enableServerResumptionTickets: true,
            enableServerEarlyData: enableServerEarlyData,
            serverResumptionTicketStore: ticketStore);

        Assert.True(serverDriver.TryConfigureServerResumptionTicketIssuance(enabled: true));
        Assert.True(serverDriver.TryConfigureServerEarlyData(enableServerEarlyData));
        Assert.Single(serverDriver.StartHandshake(CreateRememberedTransportParameters()));
        return serverDriver;
    }

    private static (byte[] ClientHello, QuicTlsPacketProtectionMaterial ZeroRttMaterial) CreateEarlyDataClientHello(
        QuicDetachedResumptionTicketSnapshot ticketSnapshot)
    {
        QuicTlsTransportBridgeDriver clientDriver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: CreateScalar(0x11));
        long nowTicks = ticketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        IReadOnlyList<QuicTlsStateUpdate> updates = clientDriver.StartHandshake(
            CreateRememberedTransportParameters(),
            ticketSnapshot,
            nowTicks);

        Assert.Equal(3, updates.Count);
        byte[] clientHello = GetCryptoData(
            updates,
            QuicTlsEncryptionLevel.Initial,
            QuicTlsHandshakeMessageType.ClientHello);
        QuicTlsPacketProtectionMaterial zeroRttMaterial =
            Assert.Single(updates, IsZeroRttMaterialUpdate).PacketProtectionMaterial!.Value;
        return (clientHello, zeroRttMaterial);
    }

    private static QuicDetachedResumptionTicketSnapshot CreateStoredEarlyDataTicketSnapshot(
        QuicServerResumptionTicketStore ticketStore)
    {
        byte[] ticketBytes = CreateSequentialBytes(0x61, 16);
        byte[] ticketNonce = CreateSequentialBytes(0x71, 8);
        byte[] resumptionMasterSecret = CreateSequentialBytes(0x81, 32);
        long capturedAtTicks = Stopwatch.GetTimestamp();
        QuicTransportParameters rememberedTransportParameters = CreateRememberedTransportParameters();

        Assert.True(ticketStore.TryStoreIssuedTicket(
            ticketBytes,
            ticketNonce,
            ticketAgeAdd: 0x01020304,
            ticketLifetimeSeconds: 600,
            resumptionMasterSecret,
            rememberedTransportParameters,
            capturedAtTicks));

        return new QuicDetachedResumptionTicketSnapshot(
            ticketBytes,
            ticketNonce,
            ticketLifetimeSeconds: 600,
            ticketAgeAdd: 0x01020304,
            capturedAtTicks,
            resumptionMasterSecret,
            ticketMaxEarlyDataSize: QuicEarlyDataMaxEarlyDataSizeSentinel,
            peerTransportParameters: rememberedTransportParameters);
    }

    private static QuicTransportParameters CreateRememberedTransportParameters()
        => new()
        {
            MaxIdleTimeout = 30_000,
            MaxUdpPayloadSize = 1200,
            InitialMaxData = 16_384,
            InitialMaxStreamDataBidiLocal = 4_096,
            InitialMaxStreamDataBidiRemote = 4_096,
            InitialMaxStreamDataUni = 4_096,
            InitialMaxStreamsBidi = 4,
            InitialMaxStreamsUni = 4,
            ActiveConnectionIdLimit = 2,
        };

    private static byte[] BuildProtectedZeroRttPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material)
    {
        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TrySetInitialDestinationConnectionId(PacketConnectionId));
        Assert.True(coordinator.TrySetSourceConnectionId(PacketSourceConnectionId));
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            applicationPayload,
            material,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    private static byte[] GetCryptoData(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        QuicTlsEncryptionLevel encryptionLevel,
        QuicTlsHandshakeMessageType messageType)
    {
        byte[]? cryptoData = updates
            .Where(update =>
                update.Kind == QuicTlsUpdateKind.CryptoDataAvailable
                && update.EncryptionLevel == encryptionLevel
                && update.CryptoData.Length > 0
                && update.CryptoData.Span[0] == (byte)messageType)
            .Select(update => update.CryptoData.ToArray())
            .SingleOrDefault();
        Assert.NotNull(cryptoData);
        return cryptoData!;
    }

    private static bool IsZeroRttMaterialUpdate(QuicTlsStateUpdate update)
        => update.Kind == QuicTlsUpdateKind.PacketProtectionMaterialAvailable
            && update.PacketProtectionMaterial?.EncryptionLevel == QuicTlsEncryptionLevel.ZeroRtt;

    private static bool TryParseNewSessionTicketEarlyData(
        ReadOnlySpan<byte> message,
        out IssuedTicket issuedTicket,
        out uint maxEarlyDataSize)
    {
        issuedTicket = default!;
        maxEarlyDataSize = default;

        if (message.Length < HandshakeHeaderLength
            || message[0] != (byte)QuicTlsHandshakeMessageType.NewSessionTicket
            || ReadUInt24(message.Slice(1, UInt24Length)) != message.Length - HandshakeHeaderLength)
        {
            return false;
        }

        int index = HandshakeHeaderLength;
        if (!TryReadUInt32(message, ref index, out uint lifetimeSeconds)
            || !TryReadUInt32(message, ref index, out uint ticketAgeAdd)
            || !TryReadUInt8(message, ref index, out int ticketNonceLength)
            || index > message.Length - ticketNonceLength)
        {
            return false;
        }

        byte[] ticketNonce = message.Slice(index, ticketNonceLength).ToArray();
        index += ticketNonceLength;
        if (!TryReadUInt16(message, ref index, out ushort ticketLength)
            || index > message.Length - ticketLength)
        {
            return false;
        }

        byte[] ticketBytes = message.Slice(index, ticketLength).ToArray();
        index += ticketLength;
        if (!TryReadUInt16(message, ref index, out ushort extensionsLength)
            || index + extensionsLength != message.Length)
        {
            return false;
        }

        int extensionsEnd = index + extensionsLength;
        while (index < extensionsEnd)
        {
            if (!TryReadUInt16(message, ref index, out ushort extensionType)
                || !TryReadUInt16(message, ref index, out ushort extensionLength)
                || index > extensionsEnd - extensionLength)
            {
                return false;
            }

            if (extensionType == EarlyDataExtensionType)
            {
                if (extensionLength != sizeof(uint))
                {
                    return false;
                }

                maxEarlyDataSize = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(index, sizeof(uint)));
                issuedTicket = new IssuedTicket(ticketBytes, ticketNonce, ticketAgeAdd, lifetimeSeconds);
                return true;
            }

            index += extensionLength;
        }

        return false;
    }

    private static bool HandshakeMessageHasZeroLengthExtension(
        ReadOnlySpan<byte> message,
        ushort expectedExtensionType)
    {
        if (message.Length < HandshakeHeaderLength + UInt16Length
            || ReadUInt24(message.Slice(1, UInt24Length)) != message.Length - HandshakeHeaderLength)
        {
            return false;
        }

        int index = HandshakeHeaderLength;
        if (!TryReadUInt16(message, ref index, out ushort extensionsLength)
            || index + extensionsLength != message.Length)
        {
            return false;
        }

        int extensionsEnd = index + extensionsLength;
        while (index < extensionsEnd)
        {
            if (!TryReadUInt16(message, ref index, out ushort extensionType)
                || !TryReadUInt16(message, ref index, out ushort extensionLength)
                || index > extensionsEnd - extensionLength)
            {
                return false;
            }

            if (extensionType == expectedExtensionType)
            {
                return extensionLength == 0;
            }

            index += extensionLength;
        }

        return false;
    }

    private static bool InitializeRuntimeActivePath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long observedAtTicks)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "InitializeActivePath",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        return (bool)method.Invoke(runtime, [pathIdentity, payloadBytes, observedAtTicks])!;
    }

    private static bool TryReadUInt8(ReadOnlySpan<byte> source, ref int index, out int value)
    {
        value = default;
        if (index >= source.Length)
        {
            return false;
        }

        value = source[index++];
        return true;
    }

    private static bool TryReadUInt16(ReadOnlySpan<byte> source, ref int index, out ushort value)
    {
        value = default;
        if (index > source.Length - UInt16Length)
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(index, UInt16Length));
        index += UInt16Length;
        return true;
    }

    private static bool TryReadUInt32(ReadOnlySpan<byte> source, ref int index, out uint value)
    {
        value = default;
        if (index > source.Length - sizeof(uint))
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(index, sizeof(uint)));
        index += sizeof(uint);
        return true;
    }

    private static int ReadUInt24(ReadOnlySpan<byte> source)
    {
        return (source[0] << 16) | (source[1] << 8) | source[2];
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }

    private sealed record IssuedTicket(
        byte[] TicketBytes,
        byte[] TicketNonce,
        uint TicketAgeAdd,
        uint TicketLifetimeSeconds);
}
