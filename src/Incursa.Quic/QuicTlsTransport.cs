// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections;
using System.Collections.Generic;

namespace Incursa.Quic;

/// <summary>
/// The endpoint role presented to the TLS bridge.
/// </summary>
internal enum QuicTlsRole
{
    Client = 0,
    Server = 1,
}

/// <summary>
/// QUIC encryption epochs surfaced to the transport.
/// </summary>
internal enum QuicTlsEncryptionLevel
{
    Initial = 0,
    ZeroRtt = 1,
    Handshake = 2,
    OneRtt = 3,
}

/// <summary>
/// TLS 1.3 handshake message types relevant to the transcript owner.
/// </summary>
internal enum QuicTlsHandshakeMessageType : byte
{
    ClientHello = 0x01,
    ServerHello = 0x02,
    NewSessionTicket = 0x04,
    EncryptedExtensions = 0x08,
    Certificate = 0x0B,
    CertificateRequest = 0x0D,
    CertificateVerify = 0x0F,
    Finished = 0x14,
    KeyUpdate = 0x18,
}

/// <summary>
/// TLS 1.3 cipher suites supported by the transcript owner.
/// </summary>
internal enum QuicTlsCipherSuite : ushort
{
    TlsAes128GcmSha256 = 0x1301,
    TlsAes256GcmSha384 = 0x1302,
    TlsChacha20Poly1305Sha256 = 0x1303,
}

/// <summary>
/// TLS 1.3 signature schemes supported by the client-role certificate proof slice.
/// </summary>
internal enum QuicTlsSignatureScheme : ushort
{
    EcdsaSecp256r1Sha256 = 0x0403,
}

/// <summary>
/// TLS 1.3 named groups supported by the managed key schedule slice.
/// </summary>
internal enum QuicTlsNamedGroup : ushort
{
    Secp256r1 = 0x0017,
    X25519 = 0x001D,
}

/// <summary>
/// TLS transcript hash algorithms implied by the supported cipher suites.
/// </summary>
internal enum QuicTlsTranscriptHashAlgorithm
{
    Sha256 = 0,
    Sha384 = 1,
}

/// <summary>
/// Handshake transcript progress owned behind the transport-facing TLS bridge.
/// </summary>
internal enum QuicTlsTranscriptPhase
{
    AwaitingPeerHandshakeMessage = 0,
    PeerTransportParametersStaged = 1,
    Completed = 2,
    Failed = 3,
}

/// <summary>
/// The branch disposition observed for a PSK-capable resumption attempt at ServerHello.
/// </summary>
internal enum QuicTlsResumptionAttemptDisposition
{
    Unknown = 0,
    Rejected = 1,
    Accepted = 2,
}

/// <summary>
/// The branch disposition observed for peer early-data acceptance at EncryptedExtensions.
/// </summary>
internal enum QuicTlsEarlyDataDisposition
{
    Unknown = 0,
    Rejected = 1,
    Accepted = 2,
}

/// <summary>
/// TLS-to-transport state update kinds.
/// </summary>
internal enum QuicTlsUpdateKind
{
    LocalTransportParametersReady = 0,
    PeerTransportParametersCommitted = 1,
    KeysAvailable = 2,
    PeerHandshakeTranscriptCompleted = 3,
    KeyUpdateInstalled = 4,
    KeysDiscarded = 5,
    FatalAlert = 6,
    ProhibitedKeyUpdateViolation = 7,
    CryptoDataAvailable = 8,
    PacketProtectionMaterialAvailable = 9,
    TranscriptProgressed = 10,
    PeerFinishedVerified = 11,
    HandshakeOpenPacketProtectionMaterialAvailable = 12,
    HandshakeProtectPacketProtectionMaterialAvailable = 13,
    PeerCertificateVerifyVerified = 14,
    PeerCertificatePolicyAccepted = 15,
    OneRttOpenPacketProtectionMaterialAvailable = 16,
    OneRttProtectPacketProtectionMaterialAvailable = 17,
    PostHandshakeTicketAvailable = 18,
    ResumptionMasterSecretAvailable = 19,
    ResumptionAttemptDispositionAvailable = 20,
    PeerEarlyDataDispositionAvailable = 21,
    KeyLogSecretAvailable = 22,
}

/// <summary>
/// A transport-facing TLS state update.
/// </summary>
internal readonly record struct QuicTlsStateUpdate(
    QuicTlsUpdateKind Kind,
    QuicTlsEncryptionLevel? EncryptionLevel = null,
    QuicTransportParameters? TransportParameters = null,
    QuicTlsHandshakeMessageType? HandshakeMessageType = null,
    uint? HandshakeMessageLength = null,
    QuicTlsCipherSuite? SelectedCipherSuite = null,
    QuicTlsTranscriptHashAlgorithm? TranscriptHashAlgorithm = null,
    uint? KeyPhase = null,
    ushort? AlertDescription = null,
    ulong? CryptoDataOffset = null,
    ReadOnlyMemory<byte> CryptoData = default,
    QuicTlsPacketProtectionMaterial? PacketProtectionMaterial = null,
    QuicTlsTranscriptPhase? TranscriptPhase = null,
    ReadOnlyMemory<byte> TicketNonce = default,
    uint? TicketLifetimeSeconds = null,
    uint? TicketAgeAdd = null,
    uint? TicketMaxEarlyDataSize = null,
    ReadOnlyMemory<byte> ResumptionMasterSecret = default,
    QuicTlsResumptionAttemptDisposition? ResumptionAttemptDisposition = null,
    QuicTlsEarlyDataDisposition? PeerEarlyDataDisposition = null,
    ReadOnlyMemory<byte> TicketBytes = default,
    QuicTlsKeyLogSecret? KeyLogSecret = null);

/// <summary>
/// A small allocation-free batch of TLS state updates.
/// </summary>
// CONTEXT: The batch stays inline for the common case because TLS updates usually arrive in tiny
// clusters; the overflow array is only for rarer bursts that exceed four items.
// SEE: QuicTlsStateUpdateBatch
internal readonly struct QuicTlsStateUpdateBatch : IReadOnlyList<QuicTlsStateUpdate>
{
    private const int FirstIndex = 0;
    private const int SecondIndex = 1;
    private const int ThirdIndex = 2;
    private const int FourthIndex = 3;
    private const int InlineCapacity = 4;
    private const int InitialOverflowCapacity = 8;
    private const int OverflowGrowthFactor = 2;

    private readonly QuicTlsStateUpdate first;
    private readonly QuicTlsStateUpdate second;
    private readonly QuicTlsStateUpdate third;
    private readonly QuicTlsStateUpdate fourth;
    private readonly QuicTlsStateUpdate[]? overflow;
    private readonly int count;

    private QuicTlsStateUpdateBatch(QuicTlsStateUpdate first)
    {
        this.first = first;
        second = default;
        third = default;
        fourth = default;
        overflow = null;
        count = 1;
    }

    private QuicTlsStateUpdateBatch(
        QuicTlsStateUpdate first,
        QuicTlsStateUpdate second,
        QuicTlsStateUpdate third,
        QuicTlsStateUpdate fourth,
        int count)
    {
        this.first = first;
        this.second = second;
        this.third = third;
        this.fourth = fourth;
        overflow = null;
        this.count = count;
    }

    private QuicTlsStateUpdateBatch(QuicTlsStateUpdate[] overflow, int count)
    {
        first = default;
        second = default;
        third = default;
        fourth = default;
        this.overflow = overflow;
        this.count = count;
    }

    internal static QuicTlsStateUpdateBatch Empty { get; } = new();

    internal static QuicTlsStateUpdateBatch One(QuicTlsStateUpdate update)
    {
        return new QuicTlsStateUpdateBatch(update);
    }

    public int Count => count;

    public QuicTlsStateUpdate this[int index]
    {
        get
        {
            if ((uint)index >= (uint)count)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            if (overflow is not null)
            {
                return overflow[index];
            }

            return index switch
            {
                FirstIndex => first,
                SecondIndex => second,
                ThirdIndex => third,
                FourthIndex => fourth,
                _ => throw new ArgumentOutOfRangeException(nameof(index)),
            };
        }
    }

    public Enumerator GetEnumerator()
    {
        return new Enumerator(this);
    }

    IEnumerator<QuicTlsStateUpdate> IEnumerable<QuicTlsStateUpdate>.GetEnumerator()
    {
        return GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    internal struct Builder
    {
        private QuicTlsStateUpdate first;
        private QuicTlsStateUpdate second;
        private QuicTlsStateUpdate third;
        private QuicTlsStateUpdate fourth;
        private QuicTlsStateUpdate[]? overflow;
        private int count;

        internal int Count => count;

        internal void Add(QuicTlsStateUpdate update)
        {
            if (overflow is not null)
            {
                AddOverflow(update);
                return;
            }

            switch (count)
            {
                case FirstIndex:
                    first = update;
                    count = SecondIndex;
                    return;
                case SecondIndex:
                    second = update;
                    count = ThirdIndex;
                    return;
                case ThirdIndex:
                    third = update;
                    count = FourthIndex;
                    return;
                case FourthIndex:
                    fourth = update;
                    count = InlineCapacity;
                    return;
                default:
                    overflow = new QuicTlsStateUpdate[InitialOverflowCapacity];
                    overflow[FirstIndex] = first;
                    overflow[SecondIndex] = second;
                    overflow[ThirdIndex] = third;
                    overflow[FourthIndex] = fourth;
                    AddOverflow(update);
                    return;
            }
        }

        internal void AddRange(QuicTlsStateUpdateBatch updates)
        {
            for (int index = 0; index < updates.Count; index++)
            {
                Add(updates[index]);
            }
        }

        internal void AddRange(IReadOnlyList<QuicTlsStateUpdate> updates)
        {
            for (int index = 0; index < updates.Count; index++)
            {
                Add(updates[index]);
            }
        }

        internal QuicTlsStateUpdateBatch ToBatch()
        {
            return count switch
            {
                0 => Empty,
                1 => One(first),
                <= InlineCapacity => new QuicTlsStateUpdateBatch(first, second, third, fourth, count),
                _ => new QuicTlsStateUpdateBatch(overflow!, count),
            };
        }

        private void AddOverflow(QuicTlsStateUpdate update)
        {
            if (overflow is null)
            {
                throw new InvalidOperationException("The overflow buffer has not been initialized.");
            }

            if (count >= overflow.Length)
            {
                Array.Resize(ref overflow, overflow.Length * OverflowGrowthFactor);
            }

            overflow[count] = update;
            count++;
        }
    }

    internal struct Enumerator : IEnumerator<QuicTlsStateUpdate>
    {
        private readonly QuicTlsStateUpdateBatch batch;
        private int index;

        internal Enumerator(QuicTlsStateUpdateBatch batch)
        {
            this.batch = batch;
            index = -1;
        }

        public QuicTlsStateUpdate Current => batch[index];

        object IEnumerator.Current => Current;

        public bool MoveNext()
        {
            int next = index + 1;
            if (next >= batch.Count)
            {
                return false;
            }

            index = next;
            return true;
        }

        public void Reset()
        {
            index = -1;
        }

        public void Dispose()
        {
        }
    }
}

/// <summary>
/// A transport-facing bridge to a concrete TLS implementation.
/// </summary>
internal interface IQuicTlsTransportBridge
{
    /// <summary>
    /// Gets the endpoint role owned by the bridge.
    /// </summary>
    QuicTlsRole Role { get; }

    /// <summary>
    /// Starts a handshake and returns any initial state updates.
    /// </summary>
    /// <param name="localTransportParameters">The local transport parameters to advertise.</param>
    /// <returns>The state updates produced by TLS.</returns>
    QuicTlsStateUpdateBatch StartHandshake(QuicTransportParameters localTransportParameters);

    /// <summary>
    /// Processes CRYPTO payload received at one encryption level.
    /// </summary>
    /// <param name="encryptionLevel">The encryption level for the CRYPTO payload.</param>
    /// <param name="cryptoFramePayload">The CRYPTO frame payload bytes.</param>
    /// <returns>The state updates produced by TLS.</returns>
    QuicTlsStateUpdateBatch ProcessCryptoFrame(
        QuicTlsEncryptionLevel encryptionLevel,
        ReadOnlyMemory<byte> cryptoFramePayload);

    /// <summary>
    /// Commits staged peer transport parameters into the bridge.
    /// </summary>
    /// <param name="peerTransportParameters">The staged peer transport parameters to commit.</param>
    /// <returns>The state updates produced by TLS.</returns>
    QuicTlsStateUpdateBatch CommitPeerTransportParameters(
        QuicTransportParameters peerTransportParameters);
}
