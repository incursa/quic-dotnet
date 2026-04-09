namespace Incursa.Quic;

/// <summary>
/// Deterministic internal driver around the transport-facing TLS bridge state.
/// </summary>
internal sealed class QuicTlsTransportBridgeDriver : IQuicTlsTransportBridge
{
    private const ushort HandshakeTranscriptUnavailableAlertDescription = 0x0010;
    private const ushort HandshakeTranscriptParseFailureAlertDescription = 0x0032;

    private readonly QuicTransportTlsBridgeState bridgeState;
    private readonly Dictionary<QuicTlsEncryptionLevel, ulong> nextIngressOffsets = [];

    public QuicTlsTransportBridgeDriver(
        QuicTlsRole role = QuicTlsRole.Client,
        QuicTransportTlsBridgeState? bridgeState = null)
    {
        Role = role;
        this.bridgeState = bridgeState ?? new QuicTransportTlsBridgeState();
    }

    /// <summary>
    /// Gets the endpoint role owned by the driver.
    /// </summary>
    public QuicTlsRole Role { get; }

    /// <summary>
    /// Gets the underlying bridge state owned by the runtime.
    /// </summary>
    public QuicTransportTlsBridgeState State => bridgeState;

    /// <inheritdoc />
    public IReadOnlyList<QuicTlsStateUpdate> StartHandshake(QuicTransportParameters localTransportParameters)
    {
        List<QuicTlsStateUpdate> updates = [];

        AppendPublishedUpdates(updates, PublishLocalTransportParameters(localTransportParameters));
        AppendPublishedUpdates(updates, PublishKeysAvailable(QuicTlsEncryptionLevel.Handshake));
        AppendPublishedUpdates(updates, PublishDeterministicHandshakeEgress(localTransportParameters));

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

    /// <inheritdoc />
    public IReadOnlyList<QuicTlsStateUpdate> CommitPeerTransportParameters(
        QuicTransportParameters peerTransportParameters)
    {
        return PublishAuthenticatedPeerTransportParameters(peerTransportParameters);
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

        if (bridgeState.LocalTransportParameters is null || !bridgeState.HandshakeKeysAvailable)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (bridgeState.HandshakeConfirmed)
        {
            return PublishFatalAlert(HandshakeTranscriptUnavailableAlertDescription);
        }

        byte[] handshakeTranscript = new byte[bufferedBytes];
        if (!bridgeState.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            handshakeTranscript,
            out ulong offset,
            out int bytesWritten)
            || offset != 0
            || bytesWritten <= 0)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        ReadOnlySpan<byte> transcriptBytes = handshakeTranscript.AsSpan(0, bytesWritten);
        if (!TryParseHandshakeTranscript(
            transcriptBytes,
            out QuicTransportParameters peerTransportParameters))
        {
            return PublishFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        List<QuicTlsStateUpdate> updates = [];
        AppendPublishedUpdates(updates, PublishAuthenticatedPeerTransportParameters(peerTransportParameters));
        AppendPublishedUpdates(updates, PublishHandshakeConfirmed());
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
    /// Publishes authenticated peer transport parameters to the bridge state.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> PublishAuthenticatedPeerTransportParameters(
        QuicTransportParameters peerTransportParameters)
    {
        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
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
    /// Publishes handshake confirmation to the bridge state.
    /// </summary>
    public IReadOnlyList<QuicTlsStateUpdate> PublishHandshakeConfirmed()
    {
        return PublishUpdate(new QuicTlsStateUpdate(QuicTlsUpdateKind.HandshakeConfirmed));
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
        Span<byte> encodedTransportParameters = stackalloc byte[512];
        QuicTransportParameterRole parameterRole = Role == QuicTlsRole.Client
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;

        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
            localTransportParameters,
            parameterRole,
            encodedTransportParameters,
            out int bytesWritten))
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        return PublishUpdate(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.CryptoDataAvailable,
            QuicTlsEncryptionLevel.Handshake,
            CryptoDataOffset: 0,
            CryptoData: encodedTransportParameters[..bytesWritten].ToArray()));
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

    private bool TryParseHandshakeTranscript(
        ReadOnlySpan<byte> transcriptBytes,
        out QuicTransportParameters peerTransportParameters)
    {
        QuicTransportParameterRole receiverRole = Role == QuicTlsRole.Client
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;

        return QuicTransportParametersCodec.TryParseTransportParameters(
            transcriptBytes,
            receiverRole,
            out peerTransportParameters);
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
