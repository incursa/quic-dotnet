namespace Incursa.Quic;

/// <summary>
/// Tracks the transport-facing facts that a TLS bridge would publish into the connection runtime.
/// </summary>
internal sealed class QuicTransportTlsBridgeState
{
    private readonly QuicCryptoBuffer initialIngressCryptoBuffer = new();
    private readonly QuicCryptoBuffer handshakeIngressCryptoBuffer = new();
    private readonly QuicCryptoBuffer oneRttIngressCryptoBuffer = new();
    private readonly QuicCryptoBuffer initialEgressCryptoBuffer = new();
    private readonly QuicCryptoBuffer handshakeEgressCryptoBuffer = new();
    private readonly QuicOneRttKeyUpdateLifecycle oneRttKeyUpdateLifecycle = new();
    private readonly Dictionary<QuicTlsEncryptionLevel, QuicTlsPacketProtectionMaterial> packetProtectionMaterials = new();
    private readonly QuicTlsRole role;
    private QuicTlsPacketProtectionMaterial? handshakeOpenPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial? handshakeProtectPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial? oneRttOpenPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial? oneRttProtectPacketProtectionMaterial;
    private QuicAeadKeyLifecycle? currentOneRttOpenKeyLifecycle;
    private QuicAeadKeyLifecycle? currentOneRttProtectKeyLifecycle;
    private QuicAeadKeyLifecycle? retainedOldOneRttOpenKeyLifecycle;
    private QuicAeadKeyLifecycle? retainedOldOneRttProtectKeyLifecycle;
    private byte[]? postHandshakeTicketBytes;
    private byte[]? postHandshakeTicketNonce;
    private uint? postHandshakeTicketLifetimeSeconds;
    private uint? postHandshakeTicketAgeAdd;
    private uint? postHandshakeTicketMaxEarlyDataSize;
    private byte[]? resumptionMasterSecret;

    internal QuicTransportTlsBridgeState()
        : this(QuicTlsRole.Client)
    {
    }

    internal QuicTransportTlsBridgeState(QuicTlsRole role)
    {
        this.role = role;
    }

    internal QuicTlsRole Role => role;

    public QuicTransportParameters? LocalTransportParameters { get; private set; }

    public QuicTransportParameters? PeerTransportParameters { get; private set; }

    public bool PeerTransportParametersCommitted { get; private set; }

    public QuicTransportParameters? StagedPeerTransportParameters { get; private set; }

    public QuicTlsHandshakeMessageType? HandshakeMessageType { get; private set; }

    public uint? HandshakeMessageLength { get; private set; }

    public QuicTlsCipherSuite? SelectedCipherSuite { get; private set; }

    public QuicTlsTranscriptHashAlgorithm? TranscriptHashAlgorithm { get; private set; }

    public bool InitialKeysAvailable { get; private set; }

    public bool HandshakeKeysAvailable { get; private set; }

    public bool OneRttKeysAvailable { get; private set; }

    public bool PeerCertificateVerifyVerified { get; private set; }

    public bool PeerCertificatePolicyAccepted { get; private set; }

    public bool PeerHandshakeTranscriptCompleted { get; private set; }

    public bool PeerFinishedVerified { get; private set; }

    public bool KeyUpdateInstalled { get; private set; }

    public bool OldKeysDiscarded { get; private set; }

    public QuicTlsPacketProtectionMaterial? HandshakeOpenPacketProtectionMaterial => handshakeOpenPacketProtectionMaterial;

    public QuicTlsPacketProtectionMaterial? HandshakeProtectPacketProtectionMaterial => handshakeProtectPacketProtectionMaterial;

    public QuicTlsPacketProtectionMaterial? OneRttOpenPacketProtectionMaterial => oneRttOpenPacketProtectionMaterial;

    public QuicTlsPacketProtectionMaterial? OneRttProtectPacketProtectionMaterial => oneRttProtectPacketProtectionMaterial;

    public QuicTlsPacketProtectionMaterial? RetainedOldOneRttOpenPacketProtectionMaterial =>
        oneRttKeyUpdateLifecycle.RetainedOldOpenPacketProtectionMaterial;

    public QuicTlsPacketProtectionMaterial? RetainedOldOneRttProtectPacketProtectionMaterial =>
        oneRttKeyUpdateLifecycle.RetainedOldProtectPacketProtectionMaterial;

    public QuicTlsPacketProtectionMaterial? RetainedNextOneRttOpenPacketProtectionMaterial =>
        oneRttKeyUpdateLifecycle.RetainedNextOpenPacketProtectionMaterial;

    internal QuicAeadKeyLifecycle? CurrentOneRttOpenKeyLifecycle => currentOneRttOpenKeyLifecycle;

    internal QuicAeadKeyLifecycle? CurrentOneRttProtectKeyLifecycle => currentOneRttProtectKeyLifecycle;

    internal QuicAeadKeyLifecycle? RetainedOldOneRttOpenKeyLifecycle => retainedOldOneRttOpenKeyLifecycle;

    internal QuicAeadKeyLifecycle? RetainedOldOneRttProtectKeyLifecycle => retainedOldOneRttProtectKeyLifecycle;

    public ulong? RetainedOldOneRttPacketProtectionDiscardAtMicros =>
        oneRttKeyUpdateLifecycle.RetainedOldPacketProtectionDiscardAtMicros;

    public uint? RetainedOldOneRttPacketProtectionKeyPhase =>
        oneRttKeyUpdateLifecycle.RetainedOldPacketProtectionKeyPhase;

    internal bool CurrentOneRttKeyPhaseAcknowledged =>
        oneRttKeyUpdateLifecycle.CurrentPacketProtectionPhaseAcknowledged;

    internal ulong? RepeatedLocalOneRttKeyUpdateNotBeforeMicros =>
        oneRttKeyUpdateLifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros;

    public ReadOnlyMemory<byte> PostHandshakeTicketBytes => postHandshakeTicketBytes ?? ReadOnlyMemory<byte>.Empty;

    public bool HasPostHandshakeTicket => postHandshakeTicketBytes is not null;

    public ReadOnlyMemory<byte> PostHandshakeTicketNonce => postHandshakeTicketNonce ?? ReadOnlyMemory<byte>.Empty;

    public uint? PostHandshakeTicketLifetimeSeconds => postHandshakeTicketLifetimeSeconds;

    public uint? PostHandshakeTicketAgeAdd => postHandshakeTicketAgeAdd;

    public uint? PostHandshakeTicketMaxEarlyDataSize => postHandshakeTicketMaxEarlyDataSize;

    public ReadOnlyMemory<byte> ResumptionMasterSecret => resumptionMasterSecret ?? ReadOnlyMemory<byte>.Empty;

    public bool HasResumptionMasterSecret => resumptionMasterSecret is not null;

    public QuicTlsResumptionAttemptDisposition ResumptionAttemptDisposition { get; private set; } = QuicTlsResumptionAttemptDisposition.Unknown;

    private bool HasAcceptedResumptionAttempt => ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Accepted;

    public QuicTlsEarlyDataDisposition PeerEarlyDataDisposition { get; private set; } = QuicTlsEarlyDataDisposition.Unknown;

    public uint CurrentOneRttKeyPhase { get; private set; }

    public QuicTlsTranscriptPhase HandshakeTranscriptPhase { get; private set; } = QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage;

    public QuicTransportErrorCode? FatalAlertCode { get; private set; }

    public string? FatalAlertDescription { get; private set; }

    public bool HasAnyAvailableKeys => InitialKeysAvailable || HandshakeKeysAvailable || OneRttKeysAvailable;

    public bool HasAnyPacketProtectionMaterial =>
        packetProtectionMaterials.Count > 0
        || handshakeOpenPacketProtectionMaterial.HasValue
        || handshakeProtectPacketProtectionMaterial.HasValue
        || oneRttOpenPacketProtectionMaterial.HasValue
        || oneRttProtectPacketProtectionMaterial.HasValue
        || oneRttKeyUpdateLifecycle.HasPacketProtectionMaterial;

    public bool IsTerminal => FatalAlertCode.HasValue;

    /// <summary>
    /// Returns whether staged peer transport parameters may be committed through the bridge.
    /// </summary>
    internal bool CanCommitPeerTransportParameters(QuicTransportParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (role == QuicTlsRole.Server)
        {
            return CanCommitServerPeerTransportParameters(parameters);
        }

        return !IsTerminal
            && !PeerTransportParametersCommitted
            && PeerFinishedVerified
            && StagedPeerTransportParameters is not null
            && HandshakeTranscriptPhase == QuicTlsTranscriptPhase.Completed
            && HandshakeMessageType == QuicTlsHandshakeMessageType.Finished
            && HandshakeMessageLength.HasValue
            && SelectedCipherSuite.HasValue
            && TranscriptHashAlgorithm.HasValue
            && AreEquivalent(StagedPeerTransportParameters, parameters)
            && (HasAcceptedResumptionAttempt || (PeerCertificateVerifyVerified && PeerCertificatePolicyAccepted));
    }

    private bool CanCommitServerPeerTransportParameters(QuicTransportParameters parameters)
    {
        return !IsTerminal
            && !PeerTransportParametersCommitted
            && PeerFinishedVerified
            && StagedPeerTransportParameters is not null
            && HandshakeTranscriptPhase == QuicTlsTranscriptPhase.Completed
            && HandshakeMessageType == QuicTlsHandshakeMessageType.Finished
            && HandshakeMessageLength.HasValue
            && SelectedCipherSuite.HasValue
            && TranscriptHashAlgorithm.HasValue
            && AreEquivalent(StagedPeerTransportParameters, parameters);
    }

    /// <summary>
    /// Returns whether handshake transcript completion may be emitted through the bridge.
    /// </summary>
    internal bool CanEmitPeerHandshakeTranscriptCompleted()
    {
        if (role == QuicTlsRole.Server)
        {
            return !IsTerminal
                && !PeerHandshakeTranscriptCompleted
                && PeerFinishedVerified
                && StagedPeerTransportParameters is not null
                && HandshakeTranscriptPhase == QuicTlsTranscriptPhase.Completed
                && HandshakeMessageType == QuicTlsHandshakeMessageType.Finished
                && HandshakeMessageLength.HasValue
                && SelectedCipherSuite.HasValue
                && TranscriptHashAlgorithm.HasValue;
        }

        return !IsTerminal
            && !PeerHandshakeTranscriptCompleted
            && PeerFinishedVerified
            && StagedPeerTransportParameters is not null
            && HandshakeTranscriptPhase == QuicTlsTranscriptPhase.Completed
            && HandshakeMessageType == QuicTlsHandshakeMessageType.Finished
            && HandshakeMessageLength.HasValue
            && SelectedCipherSuite.HasValue
            && TranscriptHashAlgorithm.HasValue
            && (HasAcceptedResumptionAttempt || PeerCertificateVerifyVerified);
    }

    internal QuicCryptoBuffer InitialIngressCryptoBuffer => initialIngressCryptoBuffer;

    internal QuicCryptoBuffer HandshakeIngressCryptoBuffer => handshakeIngressCryptoBuffer;

    internal QuicCryptoBuffer OneRttIngressCryptoBuffer => oneRttIngressCryptoBuffer;

    internal QuicCryptoBuffer InitialEgressCryptoBuffer => initialEgressCryptoBuffer;

    internal QuicCryptoBuffer HandshakeEgressCryptoBuffer => handshakeEgressCryptoBuffer;

    public bool TryApply(QuicTlsStateUpdate update)
    {
        switch (update.Kind)
        {
            case QuicTlsUpdateKind.LocalTransportParametersReady:
                return update.TransportParameters is not null
                    && TryCommitLocalTransportParameters(update.TransportParameters);

            case QuicTlsUpdateKind.PeerTransportParametersCommitted:
                return update.TransportParameters is not null
                    && TryCommitPeerTransportParameters(update.TransportParameters);

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

            case QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted:
                return TryMarkPeerHandshakeTranscriptCompleted();

            case QuicTlsUpdateKind.PeerCertificateVerifyVerified:
                return TryMarkPeerCertificateVerifyVerified();

            case QuicTlsUpdateKind.PeerCertificatePolicyAccepted:
                return TryMarkPeerCertificatePolicyAccepted();

            case QuicTlsUpdateKind.PeerFinishedVerified:
                return TryMarkPeerFinishedVerified();

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

            case QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable:
                return update.PacketProtectionMaterial.HasValue
                    && TryStoreHandshakeOpenPacketProtectionMaterial(update.PacketProtectionMaterial.Value);

            case QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable:
                return update.PacketProtectionMaterial.HasValue
                    && TryStoreHandshakeProtectPacketProtectionMaterial(update.PacketProtectionMaterial.Value);

            case QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable:
                return update.PacketProtectionMaterial.HasValue
                    && TryStoreOneRttOpenPacketProtectionMaterial(update.PacketProtectionMaterial.Value);

            case QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable:
                return update.PacketProtectionMaterial.HasValue
                    && TryStoreOneRttProtectPacketProtectionMaterial(update.PacketProtectionMaterial.Value);

            case QuicTlsUpdateKind.ResumptionMasterSecretAvailable:
                return !update.ResumptionMasterSecret.IsEmpty
                    && TryStoreResumptionMasterSecret(update.ResumptionMasterSecret);

            case QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable:
                return update.ResumptionAttemptDisposition.HasValue
                    && TryStoreResumptionAttemptDisposition(update.ResumptionAttemptDisposition.Value);

            case QuicTlsUpdateKind.PeerEarlyDataDispositionAvailable:
                return update.PeerEarlyDataDisposition.HasValue
                    && TryStorePeerEarlyDataDisposition(update.PeerEarlyDataDisposition.Value);

            case QuicTlsUpdateKind.PostHandshakeTicketAvailable:
                return update.TranscriptPhase == QuicTlsTranscriptPhase.Completed
                    && !update.TicketBytes.IsEmpty
                    && TryStorePostHandshakeTicket(
                        update.TicketBytes,
                        update.TicketNonce,
                        update.TicketLifetimeSeconds,
                        update.TicketAgeAdd,
                        update.TicketMaxEarlyDataSize);

            case QuicTlsUpdateKind.TranscriptProgressed:
                return TryApplyTranscriptProgress(update);

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
        if (encryptionLevel == QuicTlsEncryptionLevel.Handshake)
        {
            if (handshakeProtectPacketProtectionMaterial.HasValue)
            {
                material = handshakeProtectPacketProtectionMaterial.Value;
                return true;
            }

            if (handshakeOpenPacketProtectionMaterial.HasValue)
            {
                material = handshakeOpenPacketProtectionMaterial.Value;
                return true;
            }
        }
        else if (encryptionLevel == QuicTlsEncryptionLevel.OneRtt)
        {
            if (oneRttProtectPacketProtectionMaterial.HasValue)
            {
                material = oneRttProtectPacketProtectionMaterial.Value;
                return true;
            }

            if (oneRttOpenPacketProtectionMaterial.HasValue)
            {
                material = oneRttOpenPacketProtectionMaterial.Value;
                return true;
            }
        }

        if (packetProtectionMaterials.TryGetValue(encryptionLevel, out material))
        {
            return true;
        }

        material = default;
        return false;
    }

    internal bool TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial material)
    {
        if (handshakeOpenPacketProtectionMaterial.HasValue)
        {
            material = handshakeOpenPacketProtectionMaterial.Value;
            return true;
        }

        if (packetProtectionMaterials.TryGetValue(QuicTlsEncryptionLevel.Handshake, out material))
        {
            return true;
        }

        material = default;
        return false;
    }

    internal bool TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial material)
    {
        if (handshakeProtectPacketProtectionMaterial.HasValue)
        {
            material = handshakeProtectPacketProtectionMaterial.Value;
            return true;
        }

        if (packetProtectionMaterials.TryGetValue(QuicTlsEncryptionLevel.Handshake, out material))
        {
            return true;
        }

        material = default;
        return false;
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

    public bool TryCommitPeerTransportParameters(QuicTransportParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (!CanCommitPeerTransportParameters(parameters))
        {
            return false;
        }

        QuicTransportParameters committedParameters = CloneTransportParameters(parameters);
        PeerTransportParameters = committedParameters;
        PeerTransportParametersCommitted = true;
        return true;
    }

    internal QuicTransportParameters? PeerTransportParametersSnapshot =>
        PeerTransportParameters is null
            ? null
            : CloneTransportParameters(PeerTransportParameters);

    public bool TryMarkPeerHandshakeTranscriptCompleted()
    {
        if (!CanEmitPeerHandshakeTranscriptCompleted())
        {
            return false;
        }

        PeerHandshakeTranscriptCompleted = true;
        return true;
    }

    public bool TryMarkPeerCertificateVerifyVerified()
    {
        if (!CanEmitPeerCertificateVerifyVerified())
        {
            return false;
        }

        PeerCertificateVerifyVerified = true;
        return true;
    }

    public bool TryMarkPeerCertificatePolicyAccepted()
    {
        if (!CanEmitPeerCertificatePolicyAccepted())
        {
            return false;
        }

        PeerCertificatePolicyAccepted = true;
        return true;
    }

    public bool TryMarkPeerFinishedVerified()
    {
        if (!CanEmitPeerFinishedVerified())
        {
            return false;
        }

        PeerFinishedVerified = true;
        return true;
    }

    private bool TryApplyTranscriptProgress(QuicTlsStateUpdate update)
    {
        if (IsTerminal)
        {
            return false;
        }

        if (update.HandshakeMessageType.HasValue != update.HandshakeMessageLength.HasValue)
        {
            return false;
        }

        if (update.SelectedCipherSuite.HasValue != update.TranscriptHashAlgorithm.HasValue)
        {
            return false;
        }

        if (update.SelectedCipherSuite.HasValue
            && (!update.HandshakeMessageType.HasValue
                || update.HandshakeMessageType.Value is not (QuicTlsHandshakeMessageType.ServerHello
                    or QuicTlsHandshakeMessageType.ClientHello)))
        {
            return false;
        }

        if (update.TransportParameters is not null)
        {
            if (StagedPeerTransportParameters is not null
                || update.HandshakeMessageType is not (QuicTlsHandshakeMessageType.ClientHello
                    or QuicTlsHandshakeMessageType.EncryptedExtensions))
            {
                return false;
            }

            if (update.TranscriptPhase is not (QuicTlsTranscriptPhase.PeerTransportParametersStaged
                or QuicTlsTranscriptPhase.Completed))
            {
                return false;
            }
        }
        else if (update.TranscriptPhase == QuicTlsTranscriptPhase.PeerTransportParametersStaged)
        {
            if (StagedPeerTransportParameters is null
                || update.HandshakeMessageType is not (QuicTlsHandshakeMessageType.Certificate
                    or QuicTlsHandshakeMessageType.CertificateVerify))
            {
                return false;
            }
        }

        if (update.TranscriptPhase == QuicTlsTranscriptPhase.Completed
            && StagedPeerTransportParameters is null
            && update.TransportParameters is null)
        {
            return false;
        }

        bool stateChanged = false;

        if (update.HandshakeMessageType.HasValue)
        {
            if (HandshakeMessageType != update.HandshakeMessageType)
            {
                HandshakeMessageType = update.HandshakeMessageType;
                stateChanged = true;
            }
        }

        if (update.HandshakeMessageLength.HasValue
            && HandshakeMessageLength != update.HandshakeMessageLength)
        {
            HandshakeMessageLength = update.HandshakeMessageLength;
            stateChanged = true;
        }

        if (update.SelectedCipherSuite.HasValue
            && SelectedCipherSuite != update.SelectedCipherSuite)
        {
            SelectedCipherSuite = update.SelectedCipherSuite;
            stateChanged = true;
        }

        if (update.TranscriptHashAlgorithm.HasValue
            && TranscriptHashAlgorithm != update.TranscriptHashAlgorithm)
        {
            TranscriptHashAlgorithm = update.TranscriptHashAlgorithm;
            stateChanged = true;
        }

        if (update.TransportParameters is not null)
        {
            if (!TryStagePeerTransportParameters(update.TransportParameters))
            {
                return false;
            }

            stateChanged = true;
        }

        if (update.TranscriptPhase.HasValue
            && TrySetHandshakeTranscriptPhase(update.TranscriptPhase.Value))
        {
            stateChanged = true;
        }

        return stateChanged;
    }

    private bool TryStagePeerTransportParameters(QuicTransportParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (IsTerminal)
        {
            return false;
        }

        if (StagedPeerTransportParameters is not null)
        {
            return false;
        }

        QuicTransportParameters stagedParameters = CloneTransportParameters(parameters);
        StagedPeerTransportParameters = stagedParameters;
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
        if (IsTerminal || OneRttKeysAvailable || !PeerFinishedVerified)
        {
            return false;
        }

        OneRttKeysAvailable = true;
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

    internal bool TryInstallOneRttKeyUpdate(
        QuicTlsPacketProtectionMaterial openMaterial,
        QuicTlsPacketProtectionMaterial protectMaterial)
    {
        if (IsTerminal
            || KeyUpdateInstalled
            || CurrentOneRttKeyPhase != 0
            || !oneRttOpenPacketProtectionMaterial.HasValue
            || !oneRttProtectPacketProtectionMaterial.HasValue
            || !oneRttKeyUpdateLifecycle.CanCommitNextOpenPacketProtectionMaterial(openMaterial)
            || openMaterial.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt
            || protectMaterial.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt)
        {
            return false;
        }

        if (!oneRttKeyUpdateLifecycle.TryRetainOldPacketProtectionMaterial(
            oneRttOpenPacketProtectionMaterial.Value,
            oneRttProtectPacketProtectionMaterial.Value))
        {
            return false;
        }

        CurrentOneRttKeyPhase = 1;
        OneRttKeysAvailable = true;
        retainedOldOneRttOpenKeyLifecycle = currentOneRttOpenKeyLifecycle;
        retainedOldOneRttProtectKeyLifecycle = currentOneRttProtectKeyLifecycle;
        oneRttOpenPacketProtectionMaterial = openMaterial;
        oneRttProtectPacketProtectionMaterial = protectMaterial;
        currentOneRttOpenKeyLifecycle = CreateActiveAeadKeyLifecycle(openMaterial);
        currentOneRttProtectKeyLifecycle = CreateActiveAeadKeyLifecycle(protectMaterial);
        oneRttKeyUpdateLifecycle.ClearRetainedNextOpenPacketProtectionMaterial();
        oneRttKeyUpdateLifecycle.ResetRepeatedLocalPacketProtectionUpdateEligibility();
        KeyUpdateInstalled = true;
        return true;
    }

    internal bool TryRetainNextOneRttOpenPacketProtectionMaterial(QuicTlsPacketProtectionMaterial openMaterial)
    {
        if (IsTerminal
            || KeyUpdateInstalled
            || CurrentOneRttKeyPhase != 0
            || !oneRttOpenPacketProtectionMaterial.HasValue
            || openMaterial.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt)
        {
            return false;
        }

        return oneRttKeyUpdateLifecycle.TryRetainNextOpenPacketProtectionMaterial(
            oneRttOpenPacketProtectionMaterial.Value,
            openMaterial);
    }

    internal bool TryDiscardRetainedOneRttKeyUpdateMaterial()
    {
        if (!oneRttKeyUpdateLifecycle.TryDiscardRetainedOldPacketProtectionMaterial())
        {
            return false;
        }

        retainedOldOneRttOpenKeyLifecycle = null;
        retainedOldOneRttProtectKeyLifecycle = null;
        return true;
    }

    internal bool TryArmRetainedOneRttKeyUpdateMaterialDiscard(
        ulong discardAtMicros,
        uint keyPhase)
    {
        return !IsTerminal
            && oneRttKeyUpdateLifecycle.TryArmRetainedOldPacketProtectionMaterialDiscard(
                discardAtMicros,
                keyPhase);
    }

    internal bool TryRecordCurrentOneRttKeyPhaseAcknowledgment(
        ulong acknowledgedAtMicros,
        ulong probeTimeoutMicros)
    {
        return !IsTerminal
            && KeyUpdateInstalled
            && CurrentOneRttKeyPhase != 0
            && oneRttKeyUpdateLifecycle.TryRecordCurrentPacketProtectionPhaseAcknowledgment(
                CurrentOneRttKeyPhase,
                acknowledgedAtMicros,
                probeTimeoutMicros);
    }

    internal bool CanInitiateRepeatedLocalOneRttKeyUpdate(ulong nowMicros)
    {
        return !IsTerminal
            && KeyUpdateInstalled
            && CurrentOneRttKeyPhase != 0
            && oneRttKeyUpdateLifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(
                CurrentOneRttKeyPhase,
                nowMicros);
    }

    internal bool TryRecordCurrentOneRttProtectionUse()
    {
        return !IsTerminal
            && currentOneRttProtectKeyLifecycle is not null
            && currentOneRttProtectKeyLifecycle.TryUseForProtection();
    }

    internal bool TryRecordCurrentOneRttOpeningUse()
    {
        return !IsTerminal
            && currentOneRttOpenKeyLifecycle is not null
            && currentOneRttOpenKeyLifecycle.TryUseForOpening();
    }

    internal bool TryRecordRetainedOldOneRttOpeningUse()
    {
        return !IsTerminal
            && retainedOldOneRttOpenKeyLifecycle is not null
            && retainedOldOneRttOpenKeyLifecycle.TryUseForOpening();
    }

    public bool TryDiscardOldKeys()
    {
        if (IsTerminal || OldKeysDiscarded)
        {
            return false;
        }

        OldKeysDiscarded = true;
        oneRttKeyUpdateLifecycle.Reset();
        ResetOneRttAeadKeyLifecycles();
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
        PeerTransportParametersCommitted = false;
        PeerCertificateVerifyVerified = false;
        PeerCertificatePolicyAccepted = false;
        PeerHandshakeTranscriptCompleted = false;
        PeerFinishedVerified = false;
        HandshakeTranscriptPhase = QuicTlsTranscriptPhase.Failed;
        StagedPeerTransportParameters = null;
        HandshakeMessageType = null;
        HandshakeMessageLength = null;
        SelectedCipherSuite = null;
        TranscriptHashAlgorithm = null;
        handshakeOpenPacketProtectionMaterial = null;
        handshakeProtectPacketProtectionMaterial = null;
        oneRttOpenPacketProtectionMaterial = null;
        oneRttProtectPacketProtectionMaterial = null;
        oneRttKeyUpdateLifecycle.Reset();
        ResetOneRttAeadKeyLifecycles();
        oneRttIngressCryptoBuffer.DiscardFutureFrames();
        postHandshakeTicketBytes = null;
        postHandshakeTicketNonce = null;
        postHandshakeTicketLifetimeSeconds = null;
        postHandshakeTicketAgeAdd = null;
        postHandshakeTicketMaxEarlyDataSize = null;
        resumptionMasterSecret = null;
        packetProtectionMaterials.Clear();
        return true;
    }

    private bool TryStoreResumptionAttemptDisposition(QuicTlsResumptionAttemptDisposition disposition)
    {
        if (IsTerminal
            || disposition == QuicTlsResumptionAttemptDisposition.Unknown
            || (ResumptionAttemptDisposition != QuicTlsResumptionAttemptDisposition.Unknown
                && ResumptionAttemptDisposition != disposition))
        {
            return false;
        }

        if (ResumptionAttemptDisposition == disposition)
        {
            return false;
        }

        ResumptionAttemptDisposition = disposition;
        bool stateChanged = true;

        if (disposition == QuicTlsResumptionAttemptDisposition.Rejected)
        {
            stateChanged |= TryDiscardKeys(QuicTlsEncryptionLevel.ZeroRtt);
        }

        return stateChanged;
    }

    private bool TryStorePeerEarlyDataDisposition(QuicTlsEarlyDataDisposition disposition)
    {
        if (IsTerminal
            || !HasAcceptedResumptionAttempt
            || disposition == QuicTlsEarlyDataDisposition.Unknown
            || (PeerEarlyDataDisposition != QuicTlsEarlyDataDisposition.Unknown
                && PeerEarlyDataDisposition != disposition))
        {
            return false;
        }

        if (PeerEarlyDataDisposition == disposition)
        {
            return false;
        }

        PeerEarlyDataDisposition = disposition;
        bool stateChanged = true;

        if (disposition == QuicTlsEarlyDataDisposition.Rejected)
        {
            stateChanged |= TryDiscardKeys(QuicTlsEncryptionLevel.ZeroRtt);
        }

        return stateChanged;
    }

    public bool TrySetHandshakeTranscriptPhase(QuicTlsTranscriptPhase transcriptPhase)
    {
        if (IsTerminal || HandshakeTranscriptPhase == transcriptPhase)
        {
            return false;
        }

        if (transcriptPhase == QuicTlsTranscriptPhase.PeerTransportParametersStaged)
        {
            if (HandshakeTranscriptPhase != QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage
                || StagedPeerTransportParameters is null)
            {
                return false;
            }
        }
        else if (transcriptPhase == QuicTlsTranscriptPhase.Completed)
        {
            if (HandshakeTranscriptPhase is QuicTlsTranscriptPhase.Completed or QuicTlsTranscriptPhase.Failed
                || StagedPeerTransportParameters is null)
            {
                return false;
            }
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

        if (!cryptoBuffer.TryAddFrame(new QuicCryptoFrame(offset, cryptoData.Span), out result))
        {
            return false;
        }

        return result != QuicCryptoBufferResult.BufferExceeded;
    }

    private QuicCryptoBuffer? GetIngressCryptoBuffer(QuicTlsEncryptionLevel encryptionLevel)
    {
        return encryptionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => initialIngressCryptoBuffer,
            QuicTlsEncryptionLevel.Handshake => handshakeIngressCryptoBuffer,
            QuicTlsEncryptionLevel.OneRtt => oneRttIngressCryptoBuffer,
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
        oneRttKeyUpdateLifecycle.ResetRepeatedLocalPacketProtectionUpdateEligibility();
        KeyUpdateInstalled = true;
        return true;
    }

    private bool TryStorePacketProtectionMaterial(QuicTlsPacketProtectionMaterial material)
    {
        if (IsTerminal || material.EncryptionLevel is not (QuicTlsEncryptionLevel.ZeroRtt or QuicTlsEncryptionLevel.Handshake or QuicTlsEncryptionLevel.OneRtt))
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

    private bool TryStoreOneRttOpenPacketProtectionMaterial(QuicTlsPacketProtectionMaterial material)
    {
        if (!TryStoreOneRttPacketProtectionMaterial(ref oneRttOpenPacketProtectionMaterial, material))
        {
            return false;
        }

        currentOneRttOpenKeyLifecycle = CreateActiveAeadKeyLifecycle(material);
        return true;
    }

    private bool TryStoreOneRttProtectPacketProtectionMaterial(QuicTlsPacketProtectionMaterial material)
    {
        if (!TryStoreOneRttPacketProtectionMaterial(ref oneRttProtectPacketProtectionMaterial, material))
        {
            return false;
        }

        currentOneRttProtectKeyLifecycle = CreateActiveAeadKeyLifecycle(material);
        return true;
    }

    internal bool TryStoreResumptionMasterSecret(ReadOnlyMemory<byte> masterSecret)
    {
        if (IsTerminal || role != QuicTlsRole.Client || masterSecret.IsEmpty)
        {
            return false;
        }

        if (resumptionMasterSecret is not null)
        {
            return false;
        }

        resumptionMasterSecret = masterSecret.ToArray();
        return true;
    }

    internal bool TryResetClientPeerHandshakeAttempt()
    {
        if (role != QuicTlsRole.Client)
        {
            return false;
        }

        bool stateChanged = PeerTransportParameters is not null
            || PeerTransportParametersCommitted
            || StagedPeerTransportParameters is not null
            || HandshakeKeysAvailable
            || OneRttKeysAvailable
            || PeerCertificateVerifyVerified
            || PeerCertificatePolicyAccepted
            || PeerHandshakeTranscriptCompleted
            || PeerFinishedVerified
            || KeyUpdateInstalled
            || CurrentOneRttKeyPhase != 0
            || HandshakeTranscriptPhase != QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage
            || FatalAlertCode.HasValue
            || FatalAlertDescription is not null
            || handshakeOpenPacketProtectionMaterial.HasValue
            || handshakeProtectPacketProtectionMaterial.HasValue
            || oneRttOpenPacketProtectionMaterial.HasValue
            || oneRttProtectPacketProtectionMaterial.HasValue
            || initialIngressCryptoBuffer.BufferedBytes > 0
            || handshakeIngressCryptoBuffer.BufferedBytes > 0
            || oneRttIngressCryptoBuffer.BufferedBytes > 0
            || handshakeEgressCryptoBuffer.BufferedBytes > 0
            || oneRttKeyUpdateLifecycle.HasPacketProtectionMaterial
            || packetProtectionMaterials.ContainsKey(QuicTlsEncryptionLevel.Handshake)
            || packetProtectionMaterials.ContainsKey(QuicTlsEncryptionLevel.OneRtt)
            || postHandshakeTicketBytes is not null
            || postHandshakeTicketNonce is not null
            || postHandshakeTicketLifetimeSeconds.HasValue
            || postHandshakeTicketAgeAdd.HasValue
            || postHandshakeTicketMaxEarlyDataSize.HasValue
            || resumptionMasterSecret is not null;

        PeerTransportParameters = null;
        PeerTransportParametersCommitted = false;
        StagedPeerTransportParameters = null;
        HandshakeKeysAvailable = false;
        OneRttKeysAvailable = false;
        PeerCertificateVerifyVerified = false;
        PeerCertificatePolicyAccepted = false;
        PeerHandshakeTranscriptCompleted = false;
        PeerFinishedVerified = false;
        KeyUpdateInstalled = false;
        OldKeysDiscarded = false;
        CurrentOneRttKeyPhase = 0;
        HandshakeTranscriptPhase = QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage;
        FatalAlertCode = null;
        FatalAlertDescription = null;
        HandshakeMessageType = null;
        HandshakeMessageLength = null;
        SelectedCipherSuite = null;
        TranscriptHashAlgorithm = null;
        handshakeOpenPacketProtectionMaterial = null;
        handshakeProtectPacketProtectionMaterial = null;
        oneRttOpenPacketProtectionMaterial = null;
        oneRttProtectPacketProtectionMaterial = null;
        oneRttKeyUpdateLifecycle.Reset();
        ResetOneRttAeadKeyLifecycles();
        initialIngressCryptoBuffer.Reset();
        handshakeIngressCryptoBuffer.Reset();
        oneRttIngressCryptoBuffer.Reset();
        handshakeEgressCryptoBuffer.Reset();
        postHandshakeTicketBytes = null;
        postHandshakeTicketNonce = null;
        postHandshakeTicketLifetimeSeconds = null;
        postHandshakeTicketAgeAdd = null;
        postHandshakeTicketMaxEarlyDataSize = null;
        resumptionMasterSecret = null;
        _ = packetProtectionMaterials.Remove(QuicTlsEncryptionLevel.Handshake);
        _ = packetProtectionMaterials.Remove(QuicTlsEncryptionLevel.OneRtt);
        return stateChanged;
    }

    private bool TryStorePostHandshakeTicket(
        ReadOnlyMemory<byte> ticketBytes,
        ReadOnlyMemory<byte> ticketNonce,
        uint? ticketLifetimeSeconds,
        uint? ticketAgeAdd,
        uint? ticketMaxEarlyDataSize)
    {
        if (IsTerminal
            || role != QuicTlsRole.Client
            || ticketBytes.IsEmpty
            || !PeerFinishedVerified
            || HandshakeTranscriptPhase != QuicTlsTranscriptPhase.Completed
            || HandshakeMessageType != QuicTlsHandshakeMessageType.Finished
            || !HandshakeMessageLength.HasValue
            || !SelectedCipherSuite.HasValue
            || !TranscriptHashAlgorithm.HasValue
            || !ticketLifetimeSeconds.HasValue
            || !ticketAgeAdd.HasValue)
        {
            return false;
        }

        if (postHandshakeTicketBytes is not null)
        {
            return false;
        }

        postHandshakeTicketBytes = ticketBytes.ToArray();
        postHandshakeTicketNonce = ticketNonce.ToArray();
        postHandshakeTicketLifetimeSeconds = ticketLifetimeSeconds;
        postHandshakeTicketAgeAdd = ticketAgeAdd;
        postHandshakeTicketMaxEarlyDataSize = ticketMaxEarlyDataSize;
        return true;
    }

    private bool CanEmitPeerFinishedVerified()
    {
        return !IsTerminal
            && !PeerFinishedVerified
            && StagedPeerTransportParameters is not null
            && HandshakeTranscriptPhase == QuicTlsTranscriptPhase.Completed
            && HandshakeMessageType == QuicTlsHandshakeMessageType.Finished
            && HandshakeMessageLength.HasValue
            && SelectedCipherSuite.HasValue
            && TranscriptHashAlgorithm.HasValue;
    }

    private bool CanEmitPeerCertificateVerifyVerified()
    {
        return !IsTerminal
            && !PeerCertificateVerifyVerified
            && StagedPeerTransportParameters is not null
            && HandshakeTranscriptPhase == QuicTlsTranscriptPhase.PeerTransportParametersStaged
            && HandshakeMessageType == QuicTlsHandshakeMessageType.CertificateVerify
            && HandshakeMessageLength.HasValue
            && SelectedCipherSuite.HasValue
            && TranscriptHashAlgorithm.HasValue;
    }

    internal bool CanEmitPeerCertificatePolicyAccepted()
    {
        return !IsTerminal
            && !PeerTransportParametersCommitted
            && !PeerCertificatePolicyAccepted
            && PeerCertificateVerifyVerified;
    }

    private bool TryDiscardPacketProtectionMaterial(QuicTlsEncryptionLevel encryptionLevel)
    {
        return encryptionLevel switch
        {
            QuicTlsEncryptionLevel.ZeroRtt
                => packetProtectionMaterials.Remove(encryptionLevel),
            QuicTlsEncryptionLevel.Handshake
                => TryDiscardHandshakePacketProtectionMaterial(encryptionLevel),
            QuicTlsEncryptionLevel.OneRtt
                => TryDiscardOneRttPacketProtectionMaterial(),
            _ => false,
        };
    }

    private bool TryStoreHandshakeOpenPacketProtectionMaterial(QuicTlsPacketProtectionMaterial material)
    {
        if (IsTerminal || material.EncryptionLevel != QuicTlsEncryptionLevel.Handshake)
        {
            return false;
        }

        if (handshakeOpenPacketProtectionMaterial.HasValue
            && handshakeOpenPacketProtectionMaterial.Value.Matches(material))
        {
            return false;
        }

        handshakeOpenPacketProtectionMaterial = material;
        return true;
    }

    private bool TryStoreHandshakeProtectPacketProtectionMaterial(QuicTlsPacketProtectionMaterial material)
    {
        if (IsTerminal || material.EncryptionLevel != QuicTlsEncryptionLevel.Handshake)
        {
            return false;
        }

        if (handshakeProtectPacketProtectionMaterial.HasValue
            && handshakeProtectPacketProtectionMaterial.Value.Matches(material))
        {
            return false;
        }

        handshakeProtectPacketProtectionMaterial = material;
        return true;
    }

    private bool TryDiscardHandshakePacketProtectionMaterial()
    {
        bool discarded = handshakeOpenPacketProtectionMaterial.HasValue
            || handshakeProtectPacketProtectionMaterial.HasValue;
        handshakeOpenPacketProtectionMaterial = null;
        handshakeProtectPacketProtectionMaterial = null;
        return discarded;
    }

    private bool TryDiscardHandshakePacketProtectionMaterial(QuicTlsEncryptionLevel encryptionLevel)
    {
        bool discardedDirectionalMaterial = TryDiscardHandshakePacketProtectionMaterial();
        bool discardedLegacyMaterial = packetProtectionMaterials.Remove(encryptionLevel);
        return discardedDirectionalMaterial || discardedLegacyMaterial;
    }

    private bool TryDiscardOneRttPacketProtectionMaterial()
    {
        bool discardedDirectionalMaterial = oneRttOpenPacketProtectionMaterial.HasValue
            || oneRttProtectPacketProtectionMaterial.HasValue
            || oneRttKeyUpdateLifecycle.HasPacketProtectionMaterial
            || currentOneRttOpenKeyLifecycle is not null
            || currentOneRttProtectKeyLifecycle is not null
            || retainedOldOneRttOpenKeyLifecycle is not null
            || retainedOldOneRttProtectKeyLifecycle is not null;
        oneRttOpenPacketProtectionMaterial = null;
        oneRttProtectPacketProtectionMaterial = null;
        oneRttKeyUpdateLifecycle.Reset();
        ResetOneRttAeadKeyLifecycles();
        bool discardedLegacyMaterial = packetProtectionMaterials.Remove(QuicTlsEncryptionLevel.OneRtt);
        return discardedDirectionalMaterial || discardedLegacyMaterial;
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

            case QuicTlsEncryptionLevel.ZeroRtt:
            {
                bool packetProtectionMaterialDiscarded = TryDiscardPacketProtectionMaterial(encryptionLevel);
                if (!packetProtectionMaterialDiscarded && OldKeysDiscarded)
                {
                    return false;
                }

                OldKeysDiscarded = true;
                return true;
            }

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

    private bool TryStoreOneRttPacketProtectionMaterial(
        ref QuicTlsPacketProtectionMaterial? target,
        QuicTlsPacketProtectionMaterial material)
    {
        if (IsTerminal
            || !PeerFinishedVerified
            || material.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt
            || target.HasValue)
        {
            return false;
        }

        target = material;
        return true;
    }

    private static QuicAeadKeyLifecycle CreateActiveAeadKeyLifecycle(QuicTlsPacketProtectionMaterial material)
    {
        QuicAeadKeyLifecycle lifecycle = new(material.UsageLimits);
        _ = lifecycle.TryActivate();
        return lifecycle;
    }

    private void ResetOneRttAeadKeyLifecycles()
    {
        currentOneRttOpenKeyLifecycle = null;
        currentOneRttProtectKeyLifecycle = null;
        retainedOldOneRttOpenKeyLifecycle = null;
        retainedOldOneRttProtectKeyLifecycle = null;
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
