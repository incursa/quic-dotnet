using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Deterministic internal driver around the transport-facing TLS bridge state.
/// </summary>
internal sealed class QuicTlsTransportBridgeDriver : IQuicTlsTransportBridge
{
    private const int HandshakeIngressDrainChunkBytes = 512;
    private const int Sha256FingerprintLength = 32;
    private const ushort PeerCertificatePolicyMismatchAlertDescription = 0x0031;

    private readonly QuicTransportTlsBridgeState bridgeState;
    private readonly QuicTlsTranscriptProgress handshakeTranscriptProgress;
    private readonly QuicTlsKeySchedule? keySchedule;
    private readonly byte[]? pinnedPeerLeafCertificateSha256;
    private readonly Dictionary<QuicTlsEncryptionLevel, ulong> nextIngressOffsets = [];

    public QuicTlsTransportBridgeDriver(
        QuicTlsRole role = QuicTlsRole.Client,
        QuicTransportTlsBridgeState? bridgeState = null,
        ReadOnlyMemory<byte> localHandshakePrivateKey = default,
        ReadOnlyMemory<byte> pinnedPeerLeafCertificateSha256 = default)
    {
        Role = role;
        this.bridgeState = bridgeState ?? new QuicTransportTlsBridgeState();
        handshakeTranscriptProgress = new QuicTlsTranscriptProgress(Role);
        keySchedule = new QuicTlsKeySchedule(Role, localHandshakePrivateKey);

        if (!pinnedPeerLeafCertificateSha256.IsEmpty)
        {
            if (Role != QuicTlsRole.Client)
            {
                throw new ArgumentException("The pinned peer leaf certificate fingerprint is only supported for the client role.", nameof(pinnedPeerLeafCertificateSha256));
            }

            if (pinnedPeerLeafCertificateSha256.Length != Sha256FingerprintLength)
            {
                throw new ArgumentException("The pinned peer leaf certificate fingerprint must be exactly 32 bytes.", nameof(pinnedPeerLeafCertificateSha256));
            }

            this.pinnedPeerLeafCertificateSha256 = pinnedPeerLeafCertificateSha256.ToArray();
        }
    }

    /// <summary>
    /// Gets the endpoint role owned by the driver.
    /// </summary>
    public QuicTlsRole Role { get; }

    /// <summary>
    /// Gets the underlying bridge state owned by the runtime.
    /// </summary>
    public QuicTransportTlsBridgeState State => bridgeState;

    /// <summary>
    /// Gets the local ephemeral handshake key share used by the managed key schedule slice.
    /// </summary>
    internal ReadOnlyMemory<byte> LocalHandshakeKeyShare => keySchedule?.LocalKeyShare ?? ReadOnlyMemory<byte>.Empty;

    /// <inheritdoc />
    public IReadOnlyList<QuicTlsStateUpdate> StartHandshake(QuicTransportParameters localTransportParameters)
    {
        List<QuicTlsStateUpdate> updates = [];

        AppendPublishedUpdates(updates, PublishLocalTransportParameters(localTransportParameters));
        if (Role == QuicTlsRole.Client)
        {
            AppendPublishedUpdates(updates, PublishDeterministicHandshakeEgress(localTransportParameters));
        }

        return updates;
    }

    /// <inheritdoc />
    public IReadOnlyList<QuicTlsStateUpdate> ProcessCryptoFrame(
        QuicTlsEncryptionLevel encryptionLevel,
        ReadOnlyMemory<byte> cryptoFramePayload)
    {
        ulong offset = GetNextIngressOffset(encryptionLevel);
        if (TryBufferIncomingCryptoData(encryptionLevel, offset, cryptoFramePayload, out _))
        {
            nextIngressOffsets[encryptionLevel] = SaturatingAdd(offset, (ulong)cryptoFramePayload.Length);
        }

        return AdvanceHandshakeTranscript(encryptionLevel);
    }

    /// <summary>
    /// Returns a committed peer-parameter update only when the bridge gate admits it.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> CommitPeerTransportParameters(
        QuicTransportParameters peerTransportParameters)
    {
        return bridgeState.CanCommitPeerTransportParameters(peerTransportParameters)
            ? PublishCommittedPeerTransportParameters(peerTransportParameters)
            : Array.Empty<QuicTlsStateUpdate>();
    }

    /// <summary>
    /// Advances the deterministic handshake transcript from the buffered inbound CRYPTO bytes.
    /// </summary>
    /// <param name="encryptionLevel">The encryption level to advance.</param>
    /// <returns>The state updates produced by the transcript step.</returns>
    public IReadOnlyList<QuicTlsStateUpdate> AdvanceHandshakeTranscript(QuicTlsEncryptionLevel encryptionLevel)
    {
        if (encryptionLevel != QuicTlsEncryptionLevel.Handshake)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (bridgeState.IsTerminal)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        int bufferedBytes = bridgeState.HandshakeIngressCryptoBuffer.BufferedBytes;
        if (bufferedBytes <= 0)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (bridgeState.LocalTransportParameters is null)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        List<QuicTlsStateUpdate> updates = [];
        DrainBufferedHandshakeCryptoIntoTranscript();
        DriveTranscriptProgress(updates);
        return updates;
    }

    /// <summary>
    /// Applies a bridge update to the underlying state.
    /// </summary>
    public bool TryApply(QuicTlsStateUpdate update)
    {
        return bridgeState.TryApply(update);
    }

    /// <summary>
    /// Publishes the local transport parameters to the bridge state.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> PublishLocalTransportParameters(
        QuicTransportParameters localTransportParameters)
    {
        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: localTransportParameters));
    }

    /// <summary>
    /// Publishes committed peer transport parameters to the bridge state.
    /// </summary>
    private IReadOnlyList<QuicTlsStateUpdate> PublishCommittedPeerTransportParameters(
        QuicTransportParameters peerTransportParameters)
    {
        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerTransportParameters));
    }

    /// <summary>
    /// Publishes that keys are available for the specified encryption level.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> PublishKeysAvailable(QuicTlsEncryptionLevel encryptionLevel)
    {
        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            encryptionLevel));
    }

    /// <summary>
    /// Publishes a key-discard update for the specified encryption level.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> PublishKeyDiscard(QuicTlsEncryptionLevel encryptionLevel)
    {
        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysDiscarded,
            encryptionLevel));
    }

    /// <summary>
    /// Publishes a fatal TLS alert into the bridge state.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> PublishFatalAlert(ushort alertDescription)
    {
        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.FatalAlert,
            AlertDescription: alertDescription));
    }

    /// <summary>
    /// Publishes the QUIC-specific TLS KeyUpdate violation into the bridge state.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> PublishProhibitedKeyUpdateViolation()
    {
        return PublishUpdate(new QuicTlsStateUpdate(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation));
    }

    /// <summary>
    /// Publishes handshake transcript progression to the bridge state.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> PublishTranscriptProgressed(
        QuicTlsTranscriptPhase transcriptPhase,
        QuicTlsHandshakeMessageType? handshakeMessageType = null,
        uint? handshakeMessageLength = null,
        QuicTlsCipherSuite? selectedCipherSuite = null,
        QuicTlsTranscriptHashAlgorithm? transcriptHashAlgorithm = null,
        QuicTransportParameters? transportParameters = null)
    {
        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            TransportParameters: transportParameters,
            HandshakeMessageType: handshakeMessageType,
            HandshakeMessageLength: handshakeMessageLength,
            SelectedCipherSuite: selectedCipherSuite,
            TranscriptHashAlgorithm: transcriptHashAlgorithm,
            TranscriptPhase: transcriptPhase));
    }

    /// <summary>
    /// Buffers inbound CRYPTO bytes into the runtime-owned bridge state.
    /// </summary>
    public bool TryBufferIncomingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        ulong offset,
        ReadOnlyMemory<byte> cryptoData,
        out QuicCryptoBufferResult result)
    {
        return bridgeState.TryBufferIncomingCryptoData(encryptionLevel, offset, cryptoData, out result);
    }

    /// <summary>
    /// Dequeues buffered inbound CRYPTO bytes from the bridge state.
    /// </summary>
    public bool TryDequeueIncomingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out int bytesWritten)
    {
        return bridgeState.TryDequeueIncomingCryptoData(encryptionLevel, destination, out bytesWritten);
    }

    /// <summary>
    /// Dequeues buffered inbound CRYPTO bytes from the bridge state together with their starting offset.
    /// </summary>
    public bool TryDequeueIncomingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out ulong offset,
        out int bytesWritten)
    {
        return bridgeState.TryDequeueIncomingCryptoData(encryptionLevel, destination, out offset, out bytesWritten);
    }

    /// <summary>
    /// Buffers outbound CRYPTO bytes into the runtime-owned bridge state.
    /// </summary>
    public bool TryBufferOutgoingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        ulong offset,
        ReadOnlyMemory<byte> cryptoData,
        out QuicCryptoBufferResult result)
    {
        return bridgeState.TryBufferOutgoingCryptoData(encryptionLevel, offset, cryptoData, out result);
    }

    /// <summary>
    /// Dequeues buffered outbound CRYPTO bytes from the bridge state.
    /// </summary>
    public bool TryDequeueOutgoingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out int bytesWritten)
    {
        return bridgeState.TryDequeueOutgoingCryptoData(encryptionLevel, destination, out bytesWritten);
    }

    /// <summary>
    /// Dequeues buffered outbound CRYPTO bytes from the bridge state together with their starting offset.
    /// </summary>
    public bool TryDequeueOutgoingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out ulong offset,
        out int bytesWritten)
    {
        return bridgeState.TryDequeueOutgoingCryptoData(encryptionLevel, destination, out offset, out bytesWritten);
    }

    /// <summary>
    /// Peeks buffered outbound CRYPTO bytes from the bridge state without consuming them.
    /// </summary>
    public bool TryPeekOutgoingCryptoData(
        QuicTlsEncryptionLevel encryptionLevel,
        Span<byte> destination,
        out ulong offset,
        out int bytesWritten)
    {
        return bridgeState.TryPeekOutgoingCryptoData(encryptionLevel, destination, out offset, out bytesWritten);
    }

    private IReadOnlyList<QuicTlsStateUpdate> PublishUpdate(QuicTlsStateUpdate update)
    {
        return bridgeState.TryApply(update) ? [update] : Array.Empty<QuicTlsStateUpdate>();
    }

    private IReadOnlyList<QuicTlsStateUpdate> PublishDeterministicHandshakeEgress(
        QuicTransportParameters localTransportParameters)
    {
        Span<byte> encodedTranscript = stackalloc byte[512];
        QuicTransportParameterRole parameterRole = Role == QuicTlsRole.Client
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;

        if (!QuicTlsTranscriptProgress.TryFormatDeterministicTransportParametersMessage(
            localTransportParameters,
            parameterRole,
            encodedTranscript,
            out int bytesWritten))
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.CryptoDataAvailable,
            QuicTlsEncryptionLevel.Handshake,
            CryptoDataOffset: 0,
            CryptoData: encodedTranscript[..bytesWritten].ToArray()));
    }

    private static void AppendPublishedUpdates(
        List<QuicTlsStateUpdate> updates,
        IReadOnlyList<QuicTlsStateUpdate> publishedUpdates)
    {
        if (publishedUpdates.Count > 0)
        {
            updates.AddRange(publishedUpdates);
        }
    }

    private void DrainBufferedHandshakeCryptoIntoTranscript()
    {
        Span<byte> cryptoBytes = stackalloc byte[HandshakeIngressDrainChunkBytes];

        while (bridgeState.HandshakeIngressCryptoBuffer.BufferedBytes > 0)
        {
            int bytesToRead = Math.Min(
                cryptoBytes.Length,
                bridgeState.HandshakeIngressCryptoBuffer.BufferedBytes);

            if (!bridgeState.TryDequeueIncomingCryptoData(
                QuicTlsEncryptionLevel.Handshake,
                cryptoBytes[..bytesToRead],
                out ulong offset,
                out int bytesWritten)
                || bytesWritten <= 0)
            {
                break;
            }

            handshakeTranscriptProgress.AppendCryptoBytes(offset, cryptoBytes[..bytesWritten]);
            if (handshakeTranscriptProgress.TerminalAlertDescription.HasValue)
            {
                break;
            }
        }
    }

    private IReadOnlyList<QuicTlsStateUpdate> PublishPeerHandshakeTranscriptCompleted()
    {
        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted,
            HandshakeMessageType: bridgeState.HandshakeMessageType,
            HandshakeMessageLength: bridgeState.HandshakeMessageLength,
            SelectedCipherSuite: bridgeState.SelectedCipherSuite,
            TranscriptHashAlgorithm: bridgeState.TranscriptHashAlgorithm,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed));
    }

    private IReadOnlyList<QuicTlsStateUpdate> PublishKeyScheduleUpdates(QuicTlsTranscriptStep step)
    {
        if (keySchedule is null)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        IReadOnlyList<QuicTlsStateUpdate> keyScheduleUpdates = keySchedule.ProcessTranscriptStep(step);
        if (keyScheduleUpdates.Count == 0)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        List<QuicTlsStateUpdate> publishedUpdates = [];
        foreach (QuicTlsStateUpdate update in keyScheduleUpdates)
        {
            IReadOnlyList<QuicTlsStateUpdate> publishedUpdate = PublishUpdate(update);
            AppendPublishedUpdates(publishedUpdates, publishedUpdate);

            if (publishedUpdate.Count > 0
                && update.Kind == QuicTlsUpdateKind.PeerCertificateVerifyVerified)
            {
                AppendPublishedUpdates(publishedUpdates, PublishPeerCertificatePolicyAcceptance());
                if (bridgeState.IsTerminal)
                {
                    return publishedUpdates;
                }
            }
        }

        return publishedUpdates;
    }

    private IReadOnlyList<QuicTlsStateUpdate> PublishPeerCertificatePolicyAcceptance()
    {
        if (pinnedPeerLeafCertificateSha256 is null
            || keySchedule is null
            || !bridgeState.CanEmitPeerCertificatePolicyAccepted())
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (!keySchedule.TryGetPeerLeafCertificateSha256Fingerprint(out byte[] peerLeafCertificateSha256))
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        try
        {
            if (!CryptographicOperations.FixedTimeEquals(pinnedPeerLeafCertificateSha256, peerLeafCertificateSha256))
            {
                return PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
            }

            return PublishUpdate(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerLeafCertificateSha256);
        }
    }

    private void DriveTranscriptProgress(List<QuicTlsStateUpdate> updates)
    {
        while (true)
        {
            QuicTlsTranscriptStep step = handshakeTranscriptProgress.Advance(Role);

            switch (step.Kind)
            {
                case QuicTlsTranscriptStepKind.None:
                    return;

                case QuicTlsTranscriptStepKind.Progressed:
                case QuicTlsTranscriptStepKind.PeerTransportParametersStaged:
                {
                    IReadOnlyList<QuicTlsStateUpdate> progressedUpdates = PublishTranscriptProgressed(
                        step.TranscriptPhase ?? QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage,
                        step.HandshakeMessageType,
                        step.HandshakeMessageLength,
                        step.HandshakeMessageType == QuicTlsHandshakeMessageType.ServerHello ? step.SelectedCipherSuite : null,
                        step.HandshakeMessageType == QuicTlsHandshakeMessageType.ServerHello ? step.TranscriptHashAlgorithm : null,
                        step.TransportParameters);
                    AppendPublishedUpdates(updates, progressedUpdates);
                    if (progressedUpdates.Count == 0)
                    {
                        return;
                    }

                    AppendPublishedUpdates(updates, PublishKeyScheduleUpdates(step));
                    if (bridgeState.IsTerminal)
                    {
                        return;
                    }

                    if (bridgeState.CanEmitPeerHandshakeTranscriptCompleted())
                    {
                        AppendPublishedUpdates(updates, PublishPeerHandshakeTranscriptCompleted());
                    }

                    break;
                }

                case QuicTlsTranscriptStepKind.Fatal:
                    if (step.AlertDescription.HasValue)
                    {
                        AppendPublishedUpdates(updates, PublishFatalAlert(step.AlertDescription.Value));
                    }

                    return;
            }
        }
    }

    private ulong GetNextIngressOffset(QuicTlsEncryptionLevel encryptionLevel)
    {
        return nextIngressOffsets.TryGetValue(encryptionLevel, out ulong offset)
            ? offset
            : 0;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }
}
