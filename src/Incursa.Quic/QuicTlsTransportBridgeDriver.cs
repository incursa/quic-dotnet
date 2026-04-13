using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic;

/// <summary>
/// Deterministic internal driver around the transport-facing TLS bridge state.
/// </summary>
internal sealed class QuicTlsTransportBridgeDriver : IQuicTlsTransportBridge
{
    private const int HandshakeIngressDrainChunkBytes = 512;
    private const int Sha256FingerprintLength = 32;
    private const ushort PeerCertificatePolicyMismatchAlertDescription = 0x0031;
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private static readonly IdnMapping s_idnMapping = new();
    private static readonly SearchValues<char> s_safeDnsChars =
        SearchValues.Create("-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz");

    private readonly QuicTransportTlsBridgeState bridgeState;
    private readonly QuicTlsTranscriptProgress handshakeTranscriptProgress;
    private readonly QuicTlsKeySchedule? keySchedule;
    private readonly QuicClientCertificatePolicySnapshot? clientCertificatePolicySnapshot;
    private readonly SslClientAuthenticationOptions? clientAuthenticationOptions;
    private readonly byte[]? pinnedPeerLeafCertificateSha256;
    private readonly RemoteCertificateValidationCallback? remoteCertificateValidationCallback;
    private X509ChainPolicy? serverClientCertificateChainPolicy;
    private X509RevocationMode serverClientCertificateRevocationCheckMode = X509RevocationMode.NoCheck;
    private RemoteCertificateValidationCallback? serverRemoteCertificateValidationCallback;
    private ReadOnlyMemory<byte> localServerLeafCertificateDer;
    private ReadOnlyMemory<byte> localServerLeafSigningPrivateKey;
    private bool serverClientCertificateRequired;
    private readonly Dictionary<QuicTlsEncryptionLevel, ulong> nextIngressOffsets = [];
    private readonly Dictionary<QuicTlsEncryptionLevel, ulong> transcriptIngressBaseOffsets = [];

    public QuicTlsTransportBridgeDriver(
        QuicTlsRole role = QuicTlsRole.Client,
        QuicTransportTlsBridgeState? bridgeState = null,
        ReadOnlyMemory<byte> localHandshakePrivateKey = default,
        ReadOnlyMemory<byte> pinnedPeerLeafCertificateSha256 = default,
        ReadOnlyMemory<byte> localServerLeafCertificateDer = default,
        ReadOnlyMemory<byte> localServerLeafSigningPrivateKey = default,
        QuicClientCertificatePolicySnapshot? clientCertificatePolicySnapshot = null,
        RemoteCertificateValidationCallback? remoteCertificateValidationCallback = null,
        SslClientAuthenticationOptions? clientAuthenticationOptions = null)
    {
        Role = role;
        this.bridgeState = bridgeState ?? new QuicTransportTlsBridgeState(role);
        handshakeTranscriptProgress = new QuicTlsTranscriptProgress(Role);
        keySchedule = new QuicTlsKeySchedule(Role, localHandshakePrivateKey);
        this.clientCertificatePolicySnapshot = clientCertificatePolicySnapshot;
        this.clientAuthenticationOptions = clientAuthenticationOptions;

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
        }

        if (clientCertificatePolicySnapshot is not null && Role != QuicTlsRole.Client)
        {
            throw new ArgumentException("The client certificate-policy snapshot is only supported for the client role.", nameof(clientCertificatePolicySnapshot));
        }

        this.pinnedPeerLeafCertificateSha256 = pinnedPeerLeafCertificateSha256.ToArray();
        this.remoteCertificateValidationCallback = remoteCertificateValidationCallback;
        this.localServerLeafCertificateDer = localServerLeafCertificateDer;
        this.localServerLeafSigningPrivateKey = localServerLeafSigningPrivateKey;
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

        if (Role == QuicTlsRole.Client
            && keySchedule is not null
            && keySchedule.TryCreateClientHello(localTransportParameters, out byte[] clientHelloBytes))
        {
            keySchedule.AppendLocalHandshakeMessage(clientHelloBytes);
            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.CryptoDataAvailable,
                QuicTlsEncryptionLevel.Initial,
                CryptoDataOffset: 0,
                CryptoData: clientHelloBytes));
        }

        return updates;
    }

    internal bool TryConfigureServerAuthenticationMaterial(
        ReadOnlyMemory<byte> certificateDer,
        ReadOnlyMemory<byte> signingPrivateKey,
        bool clientCertificateRequired = false,
        X509ChainPolicy? serverClientCertificateChainPolicy = null,
        X509RevocationMode serverClientCertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        RemoteCertificateValidationCallback? serverRemoteCertificateValidationCallback = null)
    {
        if (Role != QuicTlsRole.Server
            || certificateDer.IsEmpty
            || signingPrivateKey.IsEmpty)
        {
            return false;
        }

        if (clientCertificateRequired && serverRemoteCertificateValidationCallback is null)
        {
            return false;
        }

        if (clientCertificateRequired
            && serverClientCertificateChainPolicy is not null
            && serverClientCertificateRevocationCheckMode != X509RevocationMode.NoCheck)
        {
            return false;
        }

        if (!clientCertificateRequired
            && serverClientCertificateChainPolicy is not null)
        {
            return false;
        }

        if (!clientCertificateRequired
            && serverClientCertificateRevocationCheckMode != X509RevocationMode.NoCheck)
        {
            return false;
        }

        if (!localServerLeafCertificateDer.IsEmpty
            && !localServerLeafCertificateDer.Span.SequenceEqual(certificateDer.Span))
        {
            return false;
        }

        if (!localServerLeafSigningPrivateKey.IsEmpty
            && !localServerLeafSigningPrivateKey.Span.SequenceEqual(signingPrivateKey.Span))
        {
            return false;
        }

        localServerLeafCertificateDer = certificateDer.ToArray();
        localServerLeafSigningPrivateKey = signingPrivateKey.ToArray();
        serverClientCertificateRequired = clientCertificateRequired;
        this.serverClientCertificateChainPolicy = serverClientCertificateChainPolicy?.Clone();
        this.serverClientCertificateRevocationCheckMode = serverClientCertificateRevocationCheckMode;
        this.serverRemoteCertificateValidationCallback = serverRemoteCertificateValidationCallback;
        handshakeTranscriptProgress.ConfigureServerClientAuthentication(clientCertificateRequired);
        keySchedule?.ConfigureServerClientAuthentication(clientCertificateRequired);
        return true;
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
        if (encryptionLevel is not (QuicTlsEncryptionLevel.Initial or QuicTlsEncryptionLevel.Handshake))
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (bridgeState.IsTerminal)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (bridgeState.InitialIngressCryptoBuffer.BufferedBytes <= 0
            && bridgeState.HandshakeIngressCryptoBuffer.BufferedBytes <= 0)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (bridgeState.LocalTransportParameters is null)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        List<QuicTlsStateUpdate> updates = [];
        if (DrainBufferedCryptoIntoTranscript(QuicTlsEncryptionLevel.Initial))
        {
            DriveTranscriptProgress(updates);
            if (bridgeState.IsTerminal)
            {
                return updates;
            }
        }

        if (bridgeState.InitialIngressCryptoBuffer.BufferedBytes == 0
            && bridgeState.HandshakeIngressCryptoBuffer.BufferedBytes > 0)
        {
            if (DrainBufferedCryptoIntoTranscript(QuicTlsEncryptionLevel.Handshake))
            {
                DriveTranscriptProgress(updates);
            }
        }

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

    private static void AppendPublishedUpdates(
        List<QuicTlsStateUpdate> updates,
        IReadOnlyList<QuicTlsStateUpdate> publishedUpdates)
    {
        if (publishedUpdates.Count > 0)
        {
            updates.AddRange(publishedUpdates);
        }
    }

    private bool DrainBufferedCryptoIntoTranscript(QuicTlsEncryptionLevel encryptionLevel)
    {
        Span<byte> cryptoBytes = stackalloc byte[HandshakeIngressDrainChunkBytes];
        bool drainedAny = false;

        while (true)
        {
            int bufferedBytes = encryptionLevel == QuicTlsEncryptionLevel.Initial
                ? bridgeState.InitialIngressCryptoBuffer.BufferedBytes
                : bridgeState.HandshakeIngressCryptoBuffer.BufferedBytes;

            if (bufferedBytes <= 0)
            {
                break;
            }

            int bytesToRead = Math.Min(
                cryptoBytes.Length,
                bufferedBytes);

            if (!bridgeState.TryDequeueIncomingCryptoData(
                encryptionLevel,
                cryptoBytes[..bytesToRead],
                out ulong offset,
                out int bytesWritten)
                || bytesWritten <= 0)
            {
                break;
            }

            handshakeTranscriptProgress.AppendCryptoBytes(
                TranslateIngressOffset(encryptionLevel, offset),
                cryptoBytes[..bytesWritten]);
            drainedAny = true;
            if (handshakeTranscriptProgress.TerminalAlertDescription.HasValue)
            {
                break;
            }
        }

        return drainedAny;
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

        IReadOnlyList<QuicTlsStateUpdate> keyScheduleUpdates = keySchedule.ProcessTranscriptStep(
            step,
            bridgeState.LocalTransportParameters,
            localServerLeafCertificateDer,
            localServerLeafSigningPrivateKey);
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
        if (keySchedule is null || !bridgeState.CanEmitPeerCertificatePolicyAccepted())
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (Role == QuicTlsRole.Server && serverClientCertificateRequired)
        {
            return PublishServerClientCertificateAcceptance();
        }

        if (clientCertificatePolicySnapshot is not null)
        {
            return PublishSnapshotAcceptedPeerCertificatePolicy();
        }

        if (clientAuthenticationOptions is not null)
        {
            return PublishStandardValidationAcceptedPeerCertificatePolicy();
        }

        if (remoteCertificateValidationCallback is not null)
        {
            return PublishCallbackAcceptedPeerCertificatePolicy();
        }

        if (pinnedPeerLeafCertificateSha256 is null || pinnedPeerLeafCertificateSha256.Length == 0)
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

    private IReadOnlyList<QuicTlsStateUpdate> PublishSnapshotAcceptedPeerCertificatePolicy()
    {
        if (keySchedule is null
            || clientCertificatePolicySnapshot is null
            || !bridgeState.CanEmitPeerCertificatePolicyAccepted())
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (!clientCertificatePolicySnapshot.IsComplete)
        {
            return PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
        }

        if (!keySchedule.TryCreatePeerLeafCertificate(out X509Certificate2? peerCertificate)
            || peerCertificate is null)
        {
            return PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
        }

        using (peerCertificate)
        {
            byte[] computedTrustMaterial = [];
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(
                    clientCertificatePolicySnapshot.ExactPeerLeafCertificateDer.Span,
                    peerCertificate.RawData))
                {
                    return PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
                }

                computedTrustMaterial = SHA256.HashData(peerCertificate.RawData);
                if (!CryptographicOperations.FixedTimeEquals(
                    clientCertificatePolicySnapshot.ExplicitTrustMaterialSha256.Span,
                    computedTrustMaterial))
                {
                    return PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
                }

                return PublishUpdate(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(computedTrustMaterial);
            }
        }
    }

    private IReadOnlyList<QuicTlsStateUpdate> PublishStandardValidationAcceptedPeerCertificatePolicy()
    {
        if (keySchedule is null
            || clientAuthenticationOptions is null
            || !bridgeState.CanEmitPeerCertificatePolicyAccepted())
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (!keySchedule.TryCreatePeerLeafCertificate(out X509Certificate2? peerCertificate)
            || peerCertificate is null)
        {
            return PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
        }

        using (peerCertificate)
        using (X509Chain chain = new X509Chain())
        {
            ConfigureClientCertificateChainPolicy(chain, clientAuthenticationOptions);

            SslPolicyErrors sslPolicyErrors = ValidateStandardPeerCertificate(chain, peerCertificate, clientAuthenticationOptions);

            if (remoteCertificateValidationCallback is not null)
            {
                try
                {
                    bool accepted = remoteCertificateValidationCallback(
                        sender: this,
                        certificate: peerCertificate,
                        chain: chain,
                        sslPolicyErrors: sslPolicyErrors);

                    return accepted
                        ? PublishUpdate(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted))
                        : PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
                }
                catch (Exception ex)
                {
                    throw new QuicException(
                        QuicError.CallbackError,
                        null,
                        "The remote certificate validation callback failed.",
                        ex);
                }
            }

            return sslPolicyErrors == SslPolicyErrors.None
                ? PublishUpdate(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted))
                : PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
        }
    }

    private IReadOnlyList<QuicTlsStateUpdate> PublishCallbackAcceptedPeerCertificatePolicy()
    {
        if (remoteCertificateValidationCallback is null
            || keySchedule is null
            || !keySchedule.TryCreatePeerLeafCertificate(out X509Certificate2? peerCertificate)
            || peerCertificate is null)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        using (peerCertificate)
        {
            try
            {
                bool accepted = remoteCertificateValidationCallback(
                    sender: this,
                    certificate: peerCertificate,
                    chain: null,
                    sslPolicyErrors: SslPolicyErrors.RemoteCertificateChainErrors);

                return accepted
                    ? PublishUpdate(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted))
                    : PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
            }
            catch (Exception ex)
            {
                throw new QuicException(
                    QuicError.CallbackError,
                    null,
                    "The remote certificate validation callback failed.",
                    ex);
            }
        }
    }

    private IReadOnlyList<QuicTlsStateUpdate> PublishServerClientCertificateAcceptance()
    {
        if (serverRemoteCertificateValidationCallback is null
            || keySchedule is null
            || !keySchedule.TryCreatePeerLeafCertificate(out X509Certificate2? peerCertificate)
            || peerCertificate is null)
        {
            return PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
        }

        using (peerCertificate)
        {
            X509Chain? chain = null;
            SslPolicyErrors sslPolicyErrors = SslPolicyErrors.RemoteCertificateChainErrors;

            try
            {
                if (serverClientCertificateChainPolicy is not null)
                {
                    chain = new X509Chain();
                    ConfigureServerClientCertificateChainPolicy(chain, serverClientCertificateChainPolicy);
                    sslPolicyErrors = chain.Build(peerCertificate)
                        ? SslPolicyErrors.None
                        : SslPolicyErrors.RemoteCertificateChainErrors;
                }
                else if (serverClientCertificateRevocationCheckMode != X509RevocationMode.NoCheck)
                {
                    chain = new X509Chain();
                    ConfigureServerClientCertificateRevocationCheckMode(chain, serverClientCertificateRevocationCheckMode);
                    sslPolicyErrors = chain.Build(peerCertificate)
                        ? SslPolicyErrors.None
                        : SslPolicyErrors.RemoteCertificateChainErrors;
                }

                bool accepted = serverRemoteCertificateValidationCallback(
                    sender: this,
                    certificate: peerCertificate,
                    chain: chain,
                    sslPolicyErrors: sslPolicyErrors);

                return accepted
                    ? PublishUpdate(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted))
                    : PublishFatalAlert(PeerCertificatePolicyMismatchAlertDescription);
            }
            catch (Exception ex)
            {
                throw new QuicException(
                    QuicError.CallbackError,
                    null,
                    "The remote certificate validation callback failed.",
                    ex);
            }
            finally
            {
                chain?.Dispose();
            }
        }
    }

    private static void ConfigureServerClientCertificateChainPolicy(
        X509Chain chain,
        X509ChainPolicy serverClientCertificateChainPolicy)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(serverClientCertificateChainPolicy);

        chain.ChainPolicy = serverClientCertificateChainPolicy.Clone();

        if (chain.ChainPolicy.ApplicationPolicy.Count == 0)
        {
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthenticationOid));
        }
    }

    private static void ConfigureServerClientCertificateRevocationCheckMode(
        X509Chain chain,
        X509RevocationMode serverClientCertificateRevocationCheckMode)
    {
        ArgumentNullException.ThrowIfNull(chain);

        chain.ChainPolicy.RevocationMode = serverClientCertificateRevocationCheckMode;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

        if (chain.ChainPolicy.ApplicationPolicy.Count == 0)
        {
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthenticationOid));
        }
    }

    private static void ConfigureClientCertificateChainPolicy(
        X509Chain chain,
        SslClientAuthenticationOptions clientAuthenticationOptions)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(clientAuthenticationOptions);

        if (clientAuthenticationOptions.CertificateChainPolicy is not null)
        {
            chain.ChainPolicy = clientAuthenticationOptions.CertificateChainPolicy.Clone();
        }
        else
        {
            chain.ChainPolicy.RevocationMode = clientAuthenticationOptions.CertificateRevocationCheckMode;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        }

        if (chain.ChainPolicy.ApplicationPolicy.Count == 0)
        {
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthenticationOid));
        }
    }

    private static SslPolicyErrors ValidateStandardPeerCertificate(
        X509Chain chain,
        X509Certificate2 peerCertificate,
        SslClientAuthenticationOptions clientAuthenticationOptions)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(peerCertificate);
        ArgumentNullException.ThrowIfNull(clientAuthenticationOptions);

        SslPolicyErrors sslPolicyErrors = chain.Build(peerCertificate)
            ? SslPolicyErrors.None
            : SslPolicyErrors.RemoteCertificateChainErrors;

        if (!string.IsNullOrEmpty(clientAuthenticationOptions.TargetHost)
            && clientAuthenticationOptions.CertificateChainPolicy?.VerificationFlags.HasFlag(X509VerificationFlags.IgnoreInvalidName) != true)
        {
            string normalizedHostName = NormalizeHostName(clientAuthenticationOptions.TargetHost);
            if (!peerCertificate.MatchesHostname(normalizedHostName, allowWildcards: true, allowCommonName: true))
            {
                sslPolicyErrors |= SslPolicyErrors.RemoteCertificateNameMismatch;
            }
        }

        return sslPolicyErrors;
    }

    private static string NormalizeHostName(string? targetHost)
    {
        if (string.IsNullOrEmpty(targetHost))
        {
            return string.Empty;
        }

        targetHost = targetHost.TrimEnd('.');

        try
        {
            return s_idnMapping.GetAscii(targetHost);
        }
        catch (ArgumentException) when (IsSafeDnsString(targetHost))
        {
            // The input looks like a safe DNS string even though IDN conversion rejected it.
        }

        return targetHost;
    }

    private static bool IsSafeDnsString(ReadOnlySpan<char> name)
    {
        return !name.ContainsAnyExcept(s_safeDnsChars);
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
                    step.SelectedCipherSuite,
                    step.TranscriptHashAlgorithm,
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

    private ulong TranslateIngressOffset(QuicTlsEncryptionLevel encryptionLevel, ulong cryptoOffset)
    {
        if (!transcriptIngressBaseOffsets.TryGetValue(encryptionLevel, out ulong transcriptOffsetBase))
        {
            transcriptOffsetBase = handshakeTranscriptProgress.IngressCursor >= cryptoOffset
                ? handshakeTranscriptProgress.IngressCursor - cryptoOffset
                : 0;
            transcriptIngressBaseOffsets[encryptionLevel] = transcriptOffsetBase;
        }

        return SaturatingAdd(transcriptOffsetBase, cryptoOffset);
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }
}
