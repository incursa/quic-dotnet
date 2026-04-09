namespace Incursa.Quic;

/// <summary>
/// Tracks the transport-facing facts that a TLS bridge would publish into the connection runtime.
/// </summary>
internal sealed class QuicTransportTlsBridgeState
{
    private readonly QuicCryptoBuffer initialIngressCryptoBuffer = new();
    private readonly QuicCryptoBuffer handshakeIngressCryptoBuffer = new();
    private readonly QuicCryptoBuffer initialEgressCryptoBuffer = new();
    private readonly QuicCryptoBuffer handshakeEgressCryptoBuffer = new();
    private readonly Dictionary<QuicTlsEncryptionLevel, QuicTlsPacketProtectionMaterial> packetProtectionMaterials = new();

    public QuicTransportParameters? LocalTransportParameters { get; private set; }

    public QuicTransportParameters? PeerTransportParameters { get; private set; }

    public bool PeerTransportParametersAuthenticated { get; private set; }

    public bool InitialKeysAvailable { get; private set; }

    public bool HandshakeKeysAvailable { get; private set; }

    public bool OneRttKeysAvailable { get; private set; }

    public bool HandshakeConfirmed { get; private set; }

    public bool KeyUpdateInstalled { get; private set; }

    public bool OldKeysDiscarded { get; private set; }

    public uint CurrentOneRttKeyPhase { get; private set; }

    public QuicTlsTranscriptPhase HandshakeTranscriptPhase { get; private set; } = QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage;

    public QuicTransportErrorCode? FatalAlertCode { get; private set; }

    public string? FatalAlertDescription { get; private set; }

    public bool HasAnyAvailableKeys => InitialKeysAvailable || HandshakeKeysAvailable || OneRttKeysAvailable;

    public bool HasAnyPacketProtectionMaterial => packetProtectionMaterials.Count > 0;

    public bool IsTerminal => FatalAlertCode.HasValue;

    internal QuicCryptoBuffer InitialIngressCryptoBuffer => initialIngressCryptoBuffer;

    internal QuicCryptoBuffer HandshakeIngressCryptoBuffer => handshakeIngressCryptoBuffer;

    internal QuicCryptoBuffer InitialEgressCryptoBuffer => initialEgressCryptoBuffer;

    internal QuicCryptoBuffer HandshakeEgressCryptoBuffer => handshakeEgressCryptoBuffer;

    public bool TryApply(QuicTlsStateUpdate update)
    {
        switch (update.Kind)
        {
            case QuicTlsUpdateKind.LocalTransportParametersReady:
                return update.TransportParameters is not null
                    && TryCommitLocalTransportParameters(update.TransportParameters);

            case QuicTlsUpdateKind.PeerTransportParametersAuthenticated:
                return update.TransportParameters is not null
                    && TryAuthenticatePeerTransportParameters(update.TransportParameters);

            case QuicTlsUpdateKind.KeysAvailable:
                if (!update.EncryptionLevel.HasValue)
                {
                    return false;
                }

                return update.EncryptionLevel.Value switch
                {
                    QuicTlsEncryptionLevel.Initial => TryMarkInitialKeysAvailable(),
                    QuicTlsEncryptionLevel.Handshake => TryMarkHandshakeKeysAvailable(),
                    QuicTlsEncryptionLevel.OneRtt => TryMarkOneRttKeysAvailable(),
                    _ => false,
                };

            case QuicTlsUpdateKind.HandshakeConfirmed:
                return TryConfirmHandshake();

            case QuicTlsUpdateKind.KeyUpdateInstalled:
                if (!update.KeyPhase.HasValue)
                {
                    return false;
                }

                return TryInstallKeyUpdate(update.KeyPhase.Value);

            case QuicTlsUpdateKind.KeysDiscarded:
                if (!update.EncryptionLevel.HasValue)
                {
                    return false;
                }

                return TryDiscardKeys(update.EncryptionLevel.Value);

            case QuicTlsUpdateKind.FatalAlert:
                if (!update.AlertDescription.HasValue)
                {
                    return false;
                }

                return TryRecordFatalAlert(QuicTransportErrorCode.ProtocolViolation, $"TLS alert {update.AlertDescription.Value}.");

            case QuicTlsUpdateKind.ProhibitedKeyUpdateViolation:
                return TryRecordFatalAlert(QuicTransportErrorCode.KeyUpdateError, "TLS KeyUpdate was prohibited.");

            case QuicTlsUpdateKind.CryptoDataAvailable:
                if (!update.EncryptionLevel.HasValue || !update.CryptoDataOffset.HasValue)
                {
                    return false;
                }

                return TryBufferOutgoingCryptoData(
                    update.EncryptionLevel.Value,
                    update.CryptoDataOffset.Value,
                    update.CryptoData,
                    out _);

            case QuicTlsUpdateKind.PacketProtectionMaterialAvailable:
                return update.PacketProtectionMaterial.HasValue
                    && TryStorePacketProtectionMaterial(update.PacketProtectionMaterial.Value);

            case QuicTlsUpdateKind.TranscriptProgressed:
                return update.TranscriptPhase.HasValue
                    && TrySetHandshakeTranscriptPhase(update.TranscriptPhase.Value);

            default:
                return false;
        }
    }

    internal bool TryBufferIncomingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        ulong offset,
        ReadOnlyMemory<byte> cryptoData,
        out QuicCryptoBufferResult result)
    {
        return TryBufferCryptoData(GetIngressCryptoBuffer(encryptionLevel), offset, cryptoData, out result);
    }

    internal bool TryBufferOutgoingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        ulong offset,
        ReadOnlyMemory<byte> cryptoData,
        out QuicCryptoBufferResult result)
    {
        return TryBufferCryptoData(GetEgressCryptoBuffer(encryptionLevel), offset, cryptoData, out result);
    }

    internal bool TryDequeueIncomingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out int bytesWritten)
    {
        return TryDequeueIncomingCryptoData(encryptionLevel, destination, out _, out bytesWritten);
    }

    internal bool TryDequeueIncomingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out ulong offset,
        out int bytesWritten)
    {
        QuicCryptoBuffer? cryptoBuffer = GetIngressCryptoBuffer(encryptionLevel);
        if (cryptoBuffer is null)
        {
            offset = 0;
            bytesWritten = 0;
            return false;
        }

        return cryptoBuffer.TryDequeueContiguousData(destination, out offset, out bytesWritten);
    }

    internal bool TryDequeueOutgoingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out int bytesWritten)
    {
        return TryDequeueOutgoingCryptoData(encryptionLevel, destination, out _, out bytesWritten);
    }

    internal bool TryDequeueOutgoingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out ulong offset,
        out int bytesWritten)
    {
        QuicCryptoBuffer? cryptoBuffer = GetEgressCryptoBuffer(encryptionLevel);
        if (cryptoBuffer is null)
        {
            offset = 0;
            bytesWritten = 0;
            return false;
        }

        return cryptoBuffer.TryDequeueContiguousData(destination, out offset, out bytesWritten);
    }

    internal bool TryPeekOutgoingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out ulong offset,
        out int bytesWritten)
    {
        QuicCryptoBuffer? cryptoBuffer = GetEgressCryptoBuffer(encryptionLevel);
        if (cryptoBuffer is null)
        {
            offset = 0;
            bytesWritten = 0;
            return false;
        }

        return cryptoBuffer.TryPeekContiguousData(destination, out offset, out bytesWritten);
    }

    internal bool TryGetPacketProtectionMaterial(
        QuicTlsEncryptionLevel encryptionLevel,
        out QuicTlsPacketProtectionMaterial material)
    {
        return packetProtectionMaterials.TryGetValue(encryptionLevel, out material);
    }

    public bool TryCommitLocalTransportParameters(QuicTransportParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        QuicTransportParameters committedParameters = CloneTransportParameters(parameters);
        if (IsTerminal || AreEquivalent(LocalTransportParameters, committedParameters))
        {
            return false;
        }

        LocalTransportParameters = committedParameters;
        return true;
    }

    public bool TryAuthenticatePeerTransportParameters(QuicTransportParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        QuicTransportParameters committedParameters = CloneTransportParameters(parameters);
        if (IsTerminal || (PeerTransportParametersAuthenticated && AreEquivalent(PeerTransportParameters, committedParameters)))
        {
            return false;
        }

        PeerTransportParameters = committedParameters;
        PeerTransportParametersAuthenticated = true;
        return true;
    }

    public bool TryMarkInitialKeysAvailable()
    {
        if (IsTerminal || InitialKeysAvailable)
        {
            return false;
        }

        InitialKeysAvailable = true;
        return true;
    }

    public bool TryMarkHandshakeKeysAvailable()
    {
        if (IsTerminal || HandshakeKeysAvailable)
        {
            return false;
        }

        HandshakeKeysAvailable = true;
        return true;
    }

    public bool TryMarkOneRttKeysAvailable()
    {
        if (IsTerminal || OneRttKeysAvailable)
        {
            return false;
        }

        OneRttKeysAvailable = true;
        return true;
    }

    public bool TryConfirmHandshake()
    {
        if (IsTerminal || HandshakeConfirmed)
        {
            return false;
        }

        HandshakeConfirmed = true;
        return true;
    }

    public bool TryInstallKeyUpdate()
    {
        if (IsTerminal || KeyUpdateInstalled)
        {
            return false;
        }

        KeyUpdateInstalled = true;
        return true;
    }

    public bool TryDiscardOldKeys()
    {
        if (IsTerminal || OldKeysDiscarded)
        {
            return false;
        }

        OldKeysDiscarded = true;
        packetProtectionMaterials.Clear();
        return true;
    }

    public bool TryRecordFatalAlert(QuicTransportErrorCode alertCode, string? description = null)
    {
        if (FatalAlertCode.HasValue && FatalAlertCode.Value == alertCode && FatalAlertDescription == description)
        {
            return false;
        }

        FatalAlertCode = alertCode;
        FatalAlertDescription = description;
        InitialKeysAvailable = false;
        HandshakeKeysAvailable = false;
        OneRttKeysAvailable = false;
        KeyUpdateInstalled = false;
        OldKeysDiscarded = true;
        HandshakeTranscriptPhase = QuicTlsTranscriptPhase.Failed;
        packetProtectionMaterials.Clear();
        return true;
    }

    public bool TrySetHandshakeTranscriptPhase(QuicTlsTranscriptPhase transcriptPhase)
    {
        if (IsTerminal || HandshakeTranscriptPhase == transcriptPhase)
        {
            return false;
        }

        HandshakeTranscriptPhase = transcriptPhase;
        return true;
    }

    private bool TryBufferCryptoData(
        QuicCryptoBuffer? cryptoBuffer,
        ulong offset,
        ReadOnlyMemory<byte> cryptoData,
        out QuicCryptoBufferResult result)
    {
        result = default;

        if (IsTerminal || cryptoBuffer is null)
        {
            return false;
        }

        int bufferedBytesBefore = cryptoBuffer.BufferedBytes;
        if (!cryptoBuffer.TryAddFrame(new QuicCryptoFrame(offset, cryptoData.Span), out result))
        {
            return false;
        }

        return result != QuicCryptoBufferResult.BufferExceeded
            && cryptoBuffer.BufferedBytes != bufferedBytesBefore;
    }

    private QuicCryptoBuffer? GetIngressCryptoBuffer(QuicTlsEncryptionLevel encryptionLevel)
    {
        return encryptionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => initialIngressCryptoBuffer,
            QuicTlsEncryptionLevel.Handshake => handshakeIngressCryptoBuffer,
            _ => null,
        };
    }

    private QuicCryptoBuffer? GetEgressCryptoBuffer(QuicTlsEncryptionLevel encryptionLevel)
    {
        return encryptionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => initialEgressCryptoBuffer,
            QuicTlsEncryptionLevel.Handshake => handshakeEgressCryptoBuffer,
            _ => null,
        };
    }

    private bool TryInstallKeyUpdate(uint keyPhase)
    {
        if (IsTerminal || (KeyUpdateInstalled && CurrentOneRttKeyPhase == keyPhase))
        {
            return false;
        }

        CurrentOneRttKeyPhase = keyPhase;
        OneRttKeysAvailable = true;
        KeyUpdateInstalled = true;
        return true;
    }

    private bool TryStorePacketProtectionMaterial(QuicTlsPacketProtectionMaterial material)
    {
        if (IsTerminal || material.EncryptionLevel is not (QuicTlsEncryptionLevel.Handshake or QuicTlsEncryptionLevel.OneRtt))
        {
            return false;
        }

        if (packetProtectionMaterials.TryGetValue(material.EncryptionLevel, out QuicTlsPacketProtectionMaterial existing)
            && existing.Matches(material))
        {
            return false;
        }

        packetProtectionMaterials[material.EncryptionLevel] = material;
        return true;
    }

    private bool TryDiscardPacketProtectionMaterial(QuicTlsEncryptionLevel encryptionLevel)
    {
        return encryptionLevel switch
        {
            QuicTlsEncryptionLevel.Handshake or QuicTlsEncryptionLevel.OneRtt
                => packetProtectionMaterials.Remove(encryptionLevel),
            _ => false,
        };
    }

    private bool TryDiscardKeys(QuicTlsEncryptionLevel encryptionLevel)
    {
        if (IsTerminal)
        {
            return false;
        }

        switch (encryptionLevel)
        {
            case QuicTlsEncryptionLevel.Initial:
                if (!InitialKeysAvailable && OldKeysDiscarded)
                {
                    return false;
                }

                InitialKeysAvailable = false;
                OldKeysDiscarded = true;
                return true;

            case QuicTlsEncryptionLevel.Handshake:
            {
                bool packetProtectionMaterialDiscarded = TryDiscardPacketProtectionMaterial(encryptionLevel);
                if (!HandshakeKeysAvailable && OldKeysDiscarded && !packetProtectionMaterialDiscarded)
                {
                    return false;
                }

                HandshakeKeysAvailable = false;
                OldKeysDiscarded = true;
                return true;
            }

            case QuicTlsEncryptionLevel.OneRtt:
            {
                bool packetProtectionMaterialDiscarded = TryDiscardPacketProtectionMaterial(encryptionLevel);
                if (!OneRttKeysAvailable && OldKeysDiscarded && !packetProtectionMaterialDiscarded)
                {
                    return false;
                }

                OneRttKeysAvailable = false;
                OldKeysDiscarded = true;
                return true;
            }

            default:
                return false;
        }
    }

    private static QuicTransportParameters CloneTransportParameters(QuicTransportParameters parameters)
    {
        return new QuicTransportParameters
        {
            OriginalDestinationConnectionId = CloneBytes(parameters.OriginalDestinationConnectionId),
            MaxIdleTimeout = parameters.MaxIdleTimeout,
            StatelessResetToken = CloneBytes(parameters.StatelessResetToken),
            MaxUdpPayloadSize = parameters.MaxUdpPayloadSize,
            InitialMaxData = parameters.InitialMaxData,
            InitialMaxStreamDataBidiLocal = parameters.InitialMaxStreamDataBidiLocal,
            InitialMaxStreamDataBidiRemote = parameters.InitialMaxStreamDataBidiRemote,
            InitialMaxStreamDataUni = parameters.InitialMaxStreamDataUni,
            InitialMaxStreamsBidi = parameters.InitialMaxStreamsBidi,
            InitialMaxStreamsUni = parameters.InitialMaxStreamsUni,
            MaxAckDelay = parameters.MaxAckDelay,
            DisableActiveMigration = parameters.DisableActiveMigration,
            PreferredAddress = ClonePreferredAddress(parameters.PreferredAddress),
            ActiveConnectionIdLimit = parameters.ActiveConnectionIdLimit,
            InitialSourceConnectionId = CloneBytes(parameters.InitialSourceConnectionId),
            RetrySourceConnectionId = CloneBytes(parameters.RetrySourceConnectionId),
        };
    }

    private static QuicPreferredAddress? ClonePreferredAddress(QuicPreferredAddress? preferredAddress)
    {
        if (preferredAddress is null)
        {
            return null;
        }

        return new QuicPreferredAddress
        {
            IPv4Address = CloneBytes(preferredAddress.IPv4Address) ?? [],
            IPv4Port = preferredAddress.IPv4Port,
            IPv6Address = CloneBytes(preferredAddress.IPv6Address) ?? [],
            IPv6Port = preferredAddress.IPv6Port,
            ConnectionId = CloneBytes(preferredAddress.ConnectionId) ?? [],
            StatelessResetToken = CloneBytes(preferredAddress.StatelessResetToken) ?? [],
        };
    }

    private static byte[]? CloneBytes(byte[]? bytes)
    {
        return bytes is null ? null : bytes.ToArray();
    }

    private static bool AreEquivalent(QuicTransportParameters? left, QuicTransportParameters? right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        if (left is null || right is null)
        {
            return false;
        }

        return AreEquivalent(left.OriginalDestinationConnectionId, right.OriginalDestinationConnectionId)
            && left.MaxIdleTimeout == right.MaxIdleTimeout
            && AreEquivalent(left.StatelessResetToken, right.StatelessResetToken)
            && left.MaxUdpPayloadSize == right.MaxUdpPayloadSize
            && left.InitialMaxData == right.InitialMaxData
            && left.InitialMaxStreamDataBidiLocal == right.InitialMaxStreamDataBidiLocal
            && left.InitialMaxStreamDataBidiRemote == right.InitialMaxStreamDataBidiRemote
            && left.InitialMaxStreamDataUni == right.InitialMaxStreamDataUni
            && left.InitialMaxStreamsBidi == right.InitialMaxStreamsBidi
            && left.InitialMaxStreamsUni == right.InitialMaxStreamsUni
            && left.MaxAckDelay == right.MaxAckDelay
            && left.DisableActiveMigration == right.DisableActiveMigration
            && AreEquivalent(left.PreferredAddress, right.PreferredAddress)
            && left.ActiveConnectionIdLimit == right.ActiveConnectionIdLimit
            && AreEquivalent(left.InitialSourceConnectionId, right.InitialSourceConnectionId)
            && AreEquivalent(left.RetrySourceConnectionId, right.RetrySourceConnectionId);
    }

    private static bool AreEquivalent(QuicPreferredAddress? left, QuicPreferredAddress? right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        if (left is null || right is null)
        {
            return false;
        }

        return left.IPv4Port == right.IPv4Port
            && left.IPv6Port == right.IPv6Port
            && AreEquivalent(left.IPv4Address, right.IPv4Address)
            && AreEquivalent(left.IPv6Address, right.IPv6Address)
            && AreEquivalent(left.ConnectionId, right.ConnectionId)
            && AreEquivalent(left.StatelessResetToken, right.StatelessResetToken);
    }

    private static bool AreEquivalent(byte[]? left, byte[]? right)
    {
        return left is null
            ? right is null
            : right is not null && left.AsSpan().SequenceEqual(right);
    }
}
