// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0151")]
public sealed class REQ_QUIC_CRT_0151
{
    private const int HandshakeHeaderLength = 4;
    private const int UInt16Length = sizeof(ushort);
    private const int UInt24Length = 3;
    private const ushort PreSharedKeyExtensionType = 0x0029;

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerAcceptsLiveTicketAndDerivesMatchingPskDheHandshakeKeys()
    {
        QuicServerResumptionTicketStore ticketStore = new();
        QuicDetachedResumptionTicketSnapshot ticketSnapshot = CreateServerIssuedTicketSnapshot(ticketStore);
        (QuicTlsTransportBridgeDriver clientDriver, byte[] clientHello) =
            CreateResumptionClientHello(ticketSnapshot);
        QuicTlsTransportBridgeDriver serverDriver = CreateServerDriver(ticketStore);

        IReadOnlyList<QuicTlsStateUpdate> serverClientHelloUpdates = serverDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            clientHello);

        byte[] serverHello = GetCryptoData(
            serverClientHelloUpdates,
            QuicTlsEncryptionLevel.Initial,
            QuicTlsHandshakeMessageType.ServerHello);
        Assert.True(ServerHelloSelectsPreSharedKey(serverHello));
        Assert.Contains(
            serverClientHelloUpdates,
            update => update.Kind == QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable
                && update.ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Accepted);

        QuicTlsHandshakeMessageType[] serverFlightTypes = GetCryptoHandshakeMessageTypes(serverClientHelloUpdates);
        Assert.DoesNotContain(QuicTlsHandshakeMessageType.Certificate, serverFlightTypes);
        Assert.DoesNotContain(QuicTlsHandshakeMessageType.CertificateVerify, serverFlightTypes);

        IReadOnlyList<QuicTlsStateUpdate> clientServerHelloUpdates = clientDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverHello);

        Assert.Contains(
            clientServerHelloUpdates,
            update => update.Kind == QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable
                && update.ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Accepted);
        Assert.True(clientDriver.State.HandshakeOpenPacketProtectionMaterial.HasValue);
        Assert.True(clientDriver.State.HandshakeProtectPacketProtectionMaterial.HasValue);
        Assert.True(serverDriver.State.HandshakeOpenPacketProtectionMaterial.HasValue);
        Assert.True(serverDriver.State.HandshakeProtectPacketProtectionMaterial.HasValue);
        Assert.True(clientDriver.State.HandshakeOpenPacketProtectionMaterial.Value.Matches(
            serverDriver.State.HandshakeProtectPacketProtectionMaterial.Value));
        Assert.True(clientDriver.State.HandshakeProtectPacketProtectionMaterial.Value.Matches(
            serverDriver.State.HandshakeOpenPacketProtectionMaterial.Value));

        byte[] encryptedExtensions = GetCryptoData(
            serverClientHelloUpdates,
            QuicTlsEncryptionLevel.Handshake,
            QuicTlsHandshakeMessageType.EncryptedExtensions);
        byte[] serverFinished = GetCryptoData(
            serverClientHelloUpdates,
            QuicTlsEncryptionLevel.Handshake,
            QuicTlsHandshakeMessageType.Finished);

        _ = clientDriver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, encryptedExtensions);
        IReadOnlyList<QuicTlsStateUpdate> clientFinishedUpdates = clientDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverFinished);
        byte[] clientFinished = GetCryptoData(
            clientFinishedUpdates,
            QuicTlsEncryptionLevel.Handshake,
            QuicTlsHandshakeMessageType.Finished);

        IReadOnlyList<QuicTlsStateUpdate> serverFinishedUpdates = serverDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientFinished);

        Assert.Contains(serverFinishedUpdates, update => update.Kind == QuicTlsUpdateKind.PeerFinishedVerified);
        Assert.True(clientDriver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(serverDriver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(clientDriver.State.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(clientDriver.State.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.True(serverDriver.State.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(serverDriver.State.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.True(clientDriver.State.OneRttOpenPacketProtectionMaterial.Value.Matches(
            serverDriver.State.OneRttProtectPacketProtectionMaterial.Value));
        Assert.True(clientDriver.State.OneRttProtectPacketProtectionMaterial.Value.Matches(
            serverDriver.State.OneRttOpenPacketProtectionMaterial.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerAcceptsTicketCapturedFromCompletedClientHandshake()
    {
        QuicServerResumptionTicketStore ticketStore = new();
        QuicDetachedResumptionTicketSnapshot ticketSnapshot =
            CreateClientCapturedTicketSnapshotFromCompletedHandshake(ticketStore);
        (_, byte[] clientHello) = CreateResumptionClientHello(ticketSnapshot);
        QuicTlsTransportBridgeDriver serverDriver = CreateServerDriver(ticketStore);

        IReadOnlyList<QuicTlsStateUpdate> updates = serverDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            clientHello);

        byte[] serverHello = GetCryptoData(
            updates,
            QuicTlsEncryptionLevel.Initial,
            QuicTlsHandshakeMessageType.ServerHello);
        Assert.True(ServerHelloSelectsPreSharedKey(serverHello));
        Assert.Contains(
            updates,
            update => update.Kind == QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable
                && update.ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Accepted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRejectsUnknownExpiredDuplicateAndBinderInvalidTicketsWithoutSelectingPsk()
    {
        foreach (RejectedOfferCase rejectedCase in CreateRejectedOfferCases())
        {
            (QuicTlsTransportBridgeDriver _, byte[] clientHello) =
                CreateResumptionClientHello(rejectedCase.TicketSnapshot);
            byte[] offeredClientHello = rejectedCase.TransformClientHello(clientHello);
            QuicTlsTransportBridgeDriver serverDriver = CreateServerDriver(rejectedCase.TicketStore);

            IReadOnlyList<QuicTlsStateUpdate> updates = serverDriver.ProcessCryptoFrame(
                QuicTlsEncryptionLevel.Initial,
                offeredClientHello);

            AssertRejectedWithoutPreSharedKeySelection(
                updates,
                rejectedCase.Name,
                rejectedCase.ExpectFullHandshakeFallback);
            Assert.NotEqual(
                QuicTlsResumptionAttemptDisposition.Accepted,
                serverDriver.State.ResumptionAttemptDisposition);
        }
    }

    private static RejectedOfferCase[] CreateRejectedOfferCases()
    {
        long nowTicks = Stopwatch.GetTimestamp();
        byte[] unknownTicket = CreateSequentialBytes(0x81, 16);
        byte[] unknownNonce = CreateSequentialBytes(0x91, 4);
        byte[] unknownSecret = CreateSequentialBytes(0xA1, 32);
        QuicDetachedResumptionTicketSnapshot unknownSnapshot = CreateTicketSnapshot(
            unknownTicket,
            unknownNonce,
            ticketLifetimeSeconds: 600,
            ticketAgeAdd: 0x01020304,
            capturedAtTicks: nowTicks,
            resumptionMasterSecret: unknownSecret);

        byte[] expiredTicket = CreateSequentialBytes(0x82, 16);
        byte[] expiredNonce = CreateSequentialBytes(0x92, 4);
        byte[] expiredSecret = CreateSequentialBytes(0xA2, 32);
        QuicServerResumptionTicketStore expiredStore = new();
        long expiredIssuedAtTicks = nowTicks - (Stopwatch.Frequency * 2L);
        Assert.True(expiredStore.TryStoreIssuedTicket(
            expiredTicket,
            expiredNonce,
            ticketAgeAdd: 0x02030405,
            ticketLifetimeSeconds: 1,
            expiredSecret,
            expiredIssuedAtTicks));
        QuicDetachedResumptionTicketSnapshot expiredSnapshot = CreateTicketSnapshot(
            expiredTicket,
            expiredNonce,
            ticketLifetimeSeconds: 1,
            ticketAgeAdd: 0x02030405,
            capturedAtTicks: expiredIssuedAtTicks,
            resumptionMasterSecret: expiredSecret);

        (QuicServerResumptionTicketStore binderStore, QuicDetachedResumptionTicketSnapshot binderSnapshot) =
            CreateLiveStoredTicketSnapshot(0x83, 0x93, 0xA3, 0x03040506);
        (QuicServerResumptionTicketStore duplicateStore, QuicDetachedResumptionTicketSnapshot duplicateSnapshot) =
            CreateLiveStoredTicketSnapshot(0x84, 0x94, 0xA4, 0x04050607);

        return
        [
            new RejectedOfferCase(
                "unknown ticket identity",
                new QuicServerResumptionTicketStore(),
                unknownSnapshot,
                static clientHello => clientHello,
                ExpectFullHandshakeFallback: true),
            new RejectedOfferCase(
                "expired ticket identity",
                expiredStore,
                expiredSnapshot,
                static clientHello => clientHello,
                ExpectFullHandshakeFallback: true),
            new RejectedOfferCase(
                "binder-invalid ticket identity",
                binderStore,
                binderSnapshot,
                MutateBinder,
                ExpectFullHandshakeFallback: true),
            new RejectedOfferCase(
                "duplicate ticket identity",
                duplicateStore,
                duplicateSnapshot,
                DuplicatePreSharedKeyIdentity,
                ExpectFullHandshakeFallback: false),
        ];
    }

    private static QuicDetachedResumptionTicketSnapshot CreateServerIssuedTicketSnapshot(
        QuicServerResumptionTicketStore ticketStore)
    {
        _ = QuicPostHandshakeTicketTestSupport.CreateFinishedServerDriver(
            enableServerResumptionTickets: true,
            out IReadOnlyList<QuicTlsStateUpdate> finishedUpdates,
            ticketStore);

        byte[] newSessionTicket = GetCryptoData(
            finishedUpdates,
            QuicTlsEncryptionLevel.OneRtt,
            QuicTlsHandshakeMessageType.NewSessionTicket);
        IssuedTicket issuedTicket = ParseNewSessionTicket(newSessionTicket);
        Assert.True(ticketStore.TryGetLiveTicket(
            issuedTicket.TicketBytes,
            out QuicServerResumptionTicketRecord storedTicket));

        return CreateTicketSnapshot(
            issuedTicket.TicketBytes,
            issuedTicket.TicketNonce,
            issuedTicket.TicketLifetimeSeconds,
            issuedTicket.TicketAgeAdd,
            Stopwatch.GetTimestamp(),
            storedTicket.ResumptionMasterSecret);
    }

    private static QuicDetachedResumptionTicketSnapshot CreateClientCapturedTicketSnapshotFromCompletedHandshake(
        QuicServerResumptionTicketStore ticketStore)
    {
        byte[] clientHandshakePrivateKey = CreateScalar(0x11);
        byte[] serverHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        using ECDsa localLeafCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localLeafCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localLeafCertificateKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(localLeafCertificateDer);

        QuicTlsTransportBridgeDriver clientDriver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: clientHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);
        IReadOnlyList<QuicTlsStateUpdate> clientBootstrapUpdates = clientDriver.StartHandshake(
            QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters());
        Assert.Equal(2, clientBootstrapUpdates.Count);
        byte[] clientHello = GetCryptoData(
            clientBootstrapUpdates,
            QuicTlsEncryptionLevel.Initial,
            QuicTlsHandshakeMessageType.ClientHello);

        QuicTlsTransportBridgeDriver serverDriver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: serverHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey,
            enableServerResumptionTickets: true,
            serverResumptionTicketStore: ticketStore);
        Assert.True(serverDriver.TryConfigureServerResumptionTicketIssuance(enabled: true));
        Assert.Single(serverDriver.StartHandshake(QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters()));

        IReadOnlyList<QuicTlsStateUpdate> serverFlightUpdates = serverDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHello);

        _ = clientDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            GetCryptoData(serverFlightUpdates, QuicTlsEncryptionLevel.Initial, QuicTlsHandshakeMessageType.ServerHello));
        _ = clientDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            GetCryptoData(serverFlightUpdates, QuicTlsEncryptionLevel.Handshake, QuicTlsHandshakeMessageType.EncryptedExtensions));
        _ = clientDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            GetCryptoData(serverFlightUpdates, QuicTlsEncryptionLevel.Handshake, QuicTlsHandshakeMessageType.Certificate));
        _ = clientDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            GetCryptoData(serverFlightUpdates, QuicTlsEncryptionLevel.Handshake, QuicTlsHandshakeMessageType.CertificateVerify));
        IReadOnlyList<QuicTlsStateUpdate> clientFinishedUpdates = clientDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            GetCryptoData(serverFlightUpdates, QuicTlsEncryptionLevel.Handshake, QuicTlsHandshakeMessageType.Finished));
        byte[] clientFinished = GetCryptoData(
            clientFinishedUpdates,
            QuicTlsEncryptionLevel.Handshake,
            QuicTlsHandshakeMessageType.Finished);
        Assert.True(clientDriver.State.HasResumptionMasterSecret);

        IReadOnlyList<QuicTlsStateUpdate> serverFinishedUpdates = serverDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientFinished);
        Assert.Contains(serverFinishedUpdates, update => update.Kind == QuicTlsUpdateKind.PeerFinishedVerified);
        byte[] newSessionTicket = GetCryptoData(
            serverFinishedUpdates,
            QuicTlsEncryptionLevel.OneRtt,
            QuicTlsHandshakeMessageType.NewSessionTicket);
        IssuedTicket issuedTicket = ParseNewSessionTicket(newSessionTicket);
        Assert.True(ticketStore.TryGetLiveTicket(
            issuedTicket.TicketBytes,
            out QuicServerResumptionTicketRecord _));

        return CreateTicketSnapshot(
            issuedTicket.TicketBytes,
            issuedTicket.TicketNonce,
            issuedTicket.TicketLifetimeSeconds,
            issuedTicket.TicketAgeAdd,
            Stopwatch.GetTimestamp(),
            clientDriver.State.ResumptionMasterSecret.ToArray());
    }

    private static (QuicServerResumptionTicketStore Store, QuicDetachedResumptionTicketSnapshot Snapshot)
        CreateLiveStoredTicketSnapshot(byte ticketStart, byte nonceStart, byte secretStart, uint ticketAgeAdd)
    {
        byte[] ticket = CreateSequentialBytes(ticketStart, 16);
        byte[] nonce = CreateSequentialBytes(nonceStart, 4);
        byte[] secret = CreateSequentialBytes(secretStart, 32);
        QuicServerResumptionTicketStore store = new();
        long capturedAtTicks = Stopwatch.GetTimestamp();
        Assert.True(store.TryStoreIssuedTicket(
            ticket,
            nonce,
            ticketAgeAdd,
            ticketLifetimeSeconds: 600,
            secret,
            capturedAtTicks));

        return (store, CreateTicketSnapshot(
            ticket,
            nonce,
            ticketLifetimeSeconds: 600,
            ticketAgeAdd,
            capturedAtTicks,
            secret));
    }

    private static QuicDetachedResumptionTicketSnapshot CreateTicketSnapshot(
        byte[] ticketBytes,
        byte[] ticketNonce,
        uint ticketLifetimeSeconds,
        uint ticketAgeAdd,
        long capturedAtTicks,
        byte[] resumptionMasterSecret)
    {
        return new QuicDetachedResumptionTicketSnapshot(
            ticketBytes,
            ticketNonce,
            ticketLifetimeSeconds,
            ticketAgeAdd,
            capturedAtTicks,
            resumptionMasterSecret);
    }

    private static (QuicTlsTransportBridgeDriver Driver, byte[] ClientHello) CreateResumptionClientHello(
        QuicDetachedResumptionTicketSnapshot ticketSnapshot)
    {
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: CreateScalar(0x11));
        long nowTicks = ticketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.StartHandshake(
            QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters(),
            ticketSnapshot,
            nowTicks);

        Assert.Equal(2, updates.Count);
        byte[] clientHello = GetCryptoData(
            updates,
            QuicTlsEncryptionLevel.Initial,
            QuicTlsHandshakeMessageType.ClientHello);
        Assert.True(QuicResumptionClientHelloTestSupport.ParseClientHello(clientHello).HasPreSharedKey);
        Assert.True(QuicResumptionClientHelloTestSupport.VerifyBinder(clientHello, ticketSnapshot));
        return (driver, clientHello);
    }

    private static QuicTlsTransportBridgeDriver CreateServerDriver(QuicServerResumptionTicketStore ticketStore)
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
            serverResumptionTicketStore: ticketStore);

        Assert.True(serverDriver.TryConfigureServerResumptionTicketIssuance(enabled: true));
        Assert.Single(serverDriver.StartHandshake(QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters()));
        return serverDriver;
    }

    private static void AssertRejectedWithoutPreSharedKeySelection(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        string scenario,
        bool expectFullHandshakeFallback)
    {
        Assert.DoesNotContain(
            updates,
            update => update.Kind == QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable
                && update.ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Accepted);

        byte[]? serverHello = TryGetCryptoData(
            updates,
            QuicTlsEncryptionLevel.Initial,
            QuicTlsHandshakeMessageType.ServerHello);
        if (serverHello is not null)
        {
            Assert.False(ServerHelloSelectsPreSharedKey(serverHello), scenario);
        }

        if (expectFullHandshakeFallback)
        {
            Assert.NotNull(serverHello);
            QuicTlsHandshakeMessageType[] messageTypes = GetCryptoHandshakeMessageTypes(updates);
            Assert.Contains(QuicTlsHandshakeMessageType.EncryptedExtensions, messageTypes);
            Assert.Contains(QuicTlsHandshakeMessageType.Certificate, messageTypes);
            Assert.Contains(QuicTlsHandshakeMessageType.CertificateVerify, messageTypes);
            Assert.Contains(QuicTlsHandshakeMessageType.Finished, messageTypes);
        }
        else
        {
            Assert.Contains(updates, update => update.Kind == QuicTlsUpdateKind.FatalAlert);
        }
    }

    private static byte[] MutateBinder(byte[] clientHello)
    {
        byte[] mutated = clientHello.ToArray();
        QuicResumptionClientHelloTestSupport.ParsedClientHello parsed =
            QuicResumptionClientHelloTestSupport.ParseClientHello(mutated);
        int binderOffset = IndexOf(mutated, parsed.Binder);
        Assert.True(binderOffset >= 0);
        mutated[binderOffset + parsed.Binder.Length - 1] ^= 0x5A;
        return mutated;
    }

    private static byte[] DuplicatePreSharedKeyIdentity(byte[] clientHello)
    {
        PreSharedKeyExtensionLocation location = LocatePreSharedKeyExtension(clientHello);
        ushort identitiesLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(location.ValueOffset, UInt16Length));
        int firstIdentityOffset = location.ValueOffset + UInt16Length;
        ushort identityLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(firstIdentityOffset, UInt16Length));
        int firstIdentityEntryLength = UInt16Length + identityLength + sizeof(uint);
        byte[] firstIdentityEntry = clientHello.AsSpan(firstIdentityOffset, firstIdentityEntryLength).ToArray();
        int insertOffset = firstIdentityOffset + firstIdentityEntryLength;

        byte[] mutated = new byte[clientHello.Length + firstIdentityEntry.Length];
        clientHello.AsSpan(0, insertOffset).CopyTo(mutated);
        firstIdentityEntry.CopyTo(mutated.AsSpan(insertOffset));
        clientHello.AsSpan(insertOffset).CopyTo(mutated.AsSpan(insertOffset + firstIdentityEntry.Length));

        WriteUInt24(mutated.AsSpan(1, UInt24Length), (uint)(clientHello.Length - HandshakeHeaderLength + firstIdentityEntry.Length));
        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(location.ExtensionsLengthOffset, UInt16Length));
        BinaryPrimitives.WriteUInt16BigEndian(
            mutated.AsSpan(location.ExtensionsLengthOffset, UInt16Length),
            checked((ushort)(extensionsLength + firstIdentityEntry.Length)));
        BinaryPrimitives.WriteUInt16BigEndian(
            mutated.AsSpan(location.ExtensionLengthOffset, UInt16Length),
            checked((ushort)(location.ValueLength + firstIdentityEntry.Length)));
        BinaryPrimitives.WriteUInt16BigEndian(
            mutated.AsSpan(location.ValueOffset, UInt16Length),
            checked((ushort)(identitiesLength + firstIdentityEntry.Length)));

        return mutated;
    }

    private static IssuedTicket ParseNewSessionTicket(ReadOnlySpan<byte> newSessionTicket)
    {
        Assert.True(newSessionTicket.Length > HandshakeHeaderLength);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.NewSessionTicket, newSessionTicket[0]);
        int bodyLength = checked((int)ReadUInt24(newSessionTicket.Slice(1, UInt24Length)));
        Assert.Equal(newSessionTicket.Length - HandshakeHeaderLength, bodyLength);

        int index = HandshakeHeaderLength;
        uint ticketLifetimeSeconds = BinaryPrimitives.ReadUInt32BigEndian(newSessionTicket.Slice(index, sizeof(uint)));
        index += sizeof(uint);
        uint ticketAgeAdd = BinaryPrimitives.ReadUInt32BigEndian(newSessionTicket.Slice(index, sizeof(uint)));
        index += sizeof(uint);
        int ticketNonceLength = newSessionTicket[index++];
        byte[] ticketNonce = newSessionTicket.Slice(index, ticketNonceLength).ToArray();
        index += ticketNonceLength;
        ushort ticketLength = BinaryPrimitives.ReadUInt16BigEndian(newSessionTicket.Slice(index, UInt16Length));
        index += UInt16Length;
        byte[] ticketBytes = newSessionTicket.Slice(index, ticketLength).ToArray();
        index += ticketLength;
        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(newSessionTicket.Slice(index, UInt16Length));
        index += UInt16Length + extensionsLength;
        Assert.Equal(newSessionTicket.Length, index);

        return new IssuedTicket(ticketBytes, ticketNonce, ticketAgeAdd, ticketLifetimeSeconds);
    }

    private static byte[] GetCryptoData(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        QuicTlsEncryptionLevel encryptionLevel,
        QuicTlsHandshakeMessageType messageType)
    {
        byte[]? cryptoData = TryGetCryptoData(updates, encryptionLevel, messageType);
        Assert.NotNull(cryptoData);
        return cryptoData;
    }

    private static byte[]? TryGetCryptoData(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        QuicTlsEncryptionLevel encryptionLevel,
        QuicTlsHandshakeMessageType messageType)
    {
        return updates
            .Where(update =>
                update.Kind == QuicTlsUpdateKind.CryptoDataAvailable
                && update.EncryptionLevel == encryptionLevel
                && update.CryptoData.Length > 0
                && update.CryptoData.Span[0] == (byte)messageType)
            .Select(update => update.CryptoData.ToArray())
            .SingleOrDefault();
    }

    private static QuicTlsHandshakeMessageType[] GetCryptoHandshakeMessageTypes(
        IReadOnlyList<QuicTlsStateUpdate> updates)
    {
        return updates
            .Where(update => update.Kind == QuicTlsUpdateKind.CryptoDataAvailable && update.CryptoData.Length > 0)
            .Select(update => (QuicTlsHandshakeMessageType)update.CryptoData.Span[0])
            .ToArray();
    }

    private static bool ServerHelloSelectsPreSharedKey(ReadOnlySpan<byte> serverHello)
    {
        if (serverHello.Length <= HandshakeHeaderLength
            || serverHello[0] != (byte)QuicTlsHandshakeMessageType.ServerHello
            || ReadUInt24(serverHello.Slice(1, UInt24Length)) != (uint)(serverHello.Length - HandshakeHeaderLength))
        {
            return false;
        }

        int index = HandshakeHeaderLength;
        index += UInt16Length;
        index += 32;
        if (!TryReadUInt8(serverHello, ref index, out int sessionIdLength)
            || !TrySkip(serverHello, ref index, sessionIdLength)
            || !TrySkip(serverHello, ref index, UInt16Length)
            || !TrySkip(serverHello, ref index, 1)
            || !TryReadUInt16(serverHello, ref index, out ushort extensionsLength)
            || index + extensionsLength != serverHello.Length)
        {
            return false;
        }

        int extensionsEnd = index + extensionsLength;
        while (index < extensionsEnd)
        {
            if (!TryReadUInt16(serverHello, ref index, out ushort extensionType)
                || !TryReadUInt16(serverHello, ref index, out ushort extensionLength)
                || index + extensionLength > extensionsEnd)
            {
                return false;
            }

            if (extensionType == PreSharedKeyExtensionType)
            {
                return extensionLength == UInt16Length
                    && BinaryPrimitives.ReadUInt16BigEndian(serverHello.Slice(index, UInt16Length)) == 0;
            }

            index += extensionLength;
        }

        return false;
    }

    private static PreSharedKeyExtensionLocation LocatePreSharedKeyExtension(byte[] clientHello)
    {
        Assert.True(clientHello.Length > HandshakeHeaderLength);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.ClientHello, clientHello[0]);
        Assert.Equal((uint)(clientHello.Length - HandshakeHeaderLength), ReadUInt24(clientHello.AsSpan(1, UInt24Length)));

        int index = HandshakeHeaderLength;
        index += UInt16Length;
        index += 32;
        int sessionIdLength = clientHello[index++];
        index += sessionIdLength;
        ushort cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(index, UInt16Length));
        index += UInt16Length + cipherSuitesLength;
        int compressionMethodsLength = clientHello[index++];
        index += compressionMethodsLength;

        int extensionsLengthOffset = index;
        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(index, UInt16Length));
        index += UInt16Length;
        int extensionsEnd = index + extensionsLength;
        while (index < extensionsEnd)
        {
            ushort extensionType = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(index, UInt16Length));
            index += UInt16Length;
            int extensionLengthOffset = index;
            ushort extensionLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.AsSpan(index, UInt16Length));
            index += UInt16Length;
            int valueOffset = index;
            index += extensionLength;

            if (extensionType == PreSharedKeyExtensionType)
            {
                return new PreSharedKeyExtensionLocation(
                    extensionsLengthOffset,
                    extensionLengthOffset,
                    valueOffset,
                    extensionLength);
            }
        }

        throw new InvalidOperationException("The ClientHello does not contain a pre_shared_key extension.");
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || needle.Length > haystack.Length)
        {
            return -1;
        }

        for (int index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.Slice(index, needle.Length).SequenceEqual(needle))
            {
                return index;
            }
        }

        return -1;
    }

    private static bool TryReadUInt8(ReadOnlySpan<byte> source, ref int index, out int value)
    {
        if ((uint)index >= (uint)source.Length)
        {
            value = default;
            return false;
        }

        value = source[index++];
        return true;
    }

    private static bool TryReadUInt16(ReadOnlySpan<byte> source, ref int index, out ushort value)
    {
        if (index > source.Length - UInt16Length)
        {
            value = default;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(index, UInt16Length));
        index += UInt16Length;
        return true;
    }

    private static bool TrySkip(ReadOnlySpan<byte> source, ref int index, int length)
    {
        if (length < 0 || index > source.Length - length)
        {
            return false;
        }

        index += length;
        return true;
    }

    private static uint ReadUInt24(ReadOnlySpan<byte> source)
    {
        return (uint)((source[0] << 16) | (source[1] << 8) | source[2]);
    }

    private static void WriteUInt24(Span<byte> destination, uint value)
    {
        destination[0] = checked((byte)(value >> 16));
        destination[1] = checked((byte)(value >> 8));
        destination[2] = checked((byte)value);
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

    private sealed record RejectedOfferCase(
        string Name,
        QuicServerResumptionTicketStore TicketStore,
        QuicDetachedResumptionTicketSnapshot TicketSnapshot,
        Func<byte[], byte[]> TransformClientHello,
        bool ExpectFullHandshakeFallback);

    private sealed record IssuedTicket(
        byte[] TicketBytes,
        byte[] TicketNonce,
        uint TicketAgeAdd,
        uint TicketLifetimeSeconds);

    private readonly record struct PreSharedKeyExtensionLocation(
        int ExtensionsLengthOffset,
        int ExtensionLengthOffset,
        int ValueOffset,
        int ValueLength);
}
