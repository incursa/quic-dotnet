using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;

#pragma warning disable S109

namespace Incursa.Quic;

/// <summary>
/// Owns the Handshake transcript progression boundary behind the transport-facing TLS bridge.
/// </summary>
internal sealed class QuicTlsTranscriptProgress
{
    private const ushort HandshakeTranscriptUnavailableAlertDescription = 0x0010;
    private const ushort HandshakeTranscriptParseFailureAlertDescription = 0x0032;
    private const int HandshakeHeaderLength = 4;
    private const int UInt16Length = 2;
    private const int UInt24Length = 3;
    private const int TlsRandomLength = 32;
    private const int CertificateVerifyMinimumLength = 2;
    private const int FinishedSha256Length = 32;
    private const int FinishedSha384Length = 48;
    private const ushort TlsLegacyVersion = 0x0303;
    private const ushort Tls13Version = 0x0304;
    private const byte NullCompressionMethod = 0x00;
    private const int MaximumSessionIdLength = 32;
    private const ushort SupportedVersionsExtensionType = 0x002b;
    private const ushort KeyShareExtensionType = 0x0033;
    private const ushort PreSharedKeyExtensionType = 0x0029;
    private const ushort PskKeyExchangeModesExtensionType = 0x002d;
    private const ushort EarlyDataExtensionType = 0x002a;
    private const ushort Secp256r1NamedGroup = (ushort)QuicTlsNamedGroup.Secp256r1;
    private const ushort TlsAes128GcmSha256Value = (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256;
    private const byte UncompressedPointFormat = 0x04;
    private const int Secp256r1CoordinateLength = 32;
    private const int Secp256r1KeyShareLength = 1 + (Secp256r1CoordinateLength * 2);
    private const byte PskDheKeMode = 0x01;

    private readonly QuicTlsRole role;
    private readonly ArrayBufferWriter<byte> partialTranscript = new();
    private readonly ArrayBufferWriter<byte> postHandshakeTranscript = new();

    private ulong ingressCursor;
    private ulong postHandshakeIngressCursor;
    private HandshakeProgressState progressState;
    private QuicTlsTranscriptPhase phase = QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage;
    private QuicTransportParameters? stagedPeerTransportParameters;
    private QuicTlsHandshakeMessageType? handshakeMessageType;
    private uint? handshakeMessageLength;
    private QuicTlsCipherSuite? selectedCipherSuite;
    private QuicTlsTranscriptHashAlgorithm? transcriptHashAlgorithm;
    private ushort? terminalAlertDescription;
    private bool serverClientCertificateRequired;
    private bool serverHelloSelectedPreSharedKey;

    /// <summary>
    /// Initializes the transcript owner for a client role by default.
    /// </summary>
    internal QuicTlsTranscriptProgress()
        : this(QuicTlsRole.Client)
    {
    }

    /// <summary>
    /// Initializes the transcript owner for a fixed endpoint role.
    /// </summary>
    internal QuicTlsTranscriptProgress(QuicTlsRole role)
    {
        this.role = role;
        progressState = role == QuicTlsRole.Server
            ? HandshakeProgressState.AwaitingClientHello
            : HandshakeProgressState.AwaitingServerHello;
    }

    internal void ConfigureServerClientAuthentication(bool clientCertificateRequired)
    {
        serverClientCertificateRequired = clientCertificateRequired;
    }

    internal ulong IngressCursor => ingressCursor;

    internal QuicTlsTranscriptPhase Phase => phase;

    internal QuicTransportParameters? StagedPeerTransportParameters => stagedPeerTransportParameters;

    internal QuicTlsHandshakeMessageType? HandshakeMessageType => handshakeMessageType;

    internal uint? HandshakeMessageLength => handshakeMessageLength;

    internal QuicTlsCipherSuite? SelectedCipherSuite => selectedCipherSuite;

    internal QuicTlsTranscriptHashAlgorithm? TranscriptHashAlgorithm => transcriptHashAlgorithm;

    internal ushort? TerminalAlertDescription => terminalAlertDescription;

    internal bool IsTerminalFailure => terminalAlertDescription.HasValue;

    internal bool HasPendingBytes => partialTranscript.WrittenCount > 0;

    internal void AppendCryptoBytes(ulong offset, ReadOnlySpan<byte> cryptoBytes)
    {
        if (terminalAlertDescription.HasValue || cryptoBytes.IsEmpty)
        {
            return;
        }

        if (phase is QuicTlsTranscriptPhase.Completed or QuicTlsTranscriptPhase.Failed)
        {
            Fail(HandshakeTranscriptUnavailableAlertDescription);
            return;
        }

        if (offset != ingressCursor)
        {
            Fail(HandshakeTranscriptParseFailureAlertDescription);
            return;
        }

        Span<byte> destination = partialTranscript.GetSpan(cryptoBytes.Length);
        cryptoBytes.CopyTo(destination);
        partialTranscript.Advance(cryptoBytes.Length);
        ingressCursor = SaturatingAdd(ingressCursor, (ulong)cryptoBytes.Length);
    }

    internal void AppendPostHandshakeCryptoBytes(ulong offset, ReadOnlySpan<byte> cryptoBytes)
    {
        if (terminalAlertDescription.HasValue
            || role != QuicTlsRole.Client
            || phase != QuicTlsTranscriptPhase.Completed
            || cryptoBytes.IsEmpty)
        {
            return;
        }

        if (offset != postHandshakeIngressCursor)
        {
            postHandshakeTranscript.Clear();
            postHandshakeIngressCursor = 0;
            return;
        }

        Span<byte> destination = postHandshakeTranscript.GetSpan(cryptoBytes.Length);
        cryptoBytes.CopyTo(destination);
        postHandshakeTranscript.Advance(cryptoBytes.Length);
        postHandshakeIngressCursor = SaturatingAdd(postHandshakeIngressCursor, (ulong)cryptoBytes.Length);
    }

    internal QuicTlsTranscriptStep Advance(QuicTlsRole role)
    {
        if (role != this.role)
        {
            Fail(HandshakeTranscriptParseFailureAlertDescription);
            return BuildFatalStep();
        }

        if (terminalAlertDescription.HasValue)
        {
            return BuildFatalStep();
        }

        if (phase == QuicTlsTranscriptPhase.Completed)
        {
            if (partialTranscript.WrittenCount > 0)
            {
                Fail(HandshakeTranscriptParseFailureAlertDescription);
                return BuildFatalStep();
            }

            return TryAdvancePostHandshakeTranscript(out QuicTlsTranscriptStep postHandshakeStep) switch
            {
                TranscriptAdvanceResult.NeedMore => new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None),
                TranscriptAdvanceResult.Progressed => postHandshakeStep,
                TranscriptAdvanceResult.Failed => BuildFatalStep(),
                _ => new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None),
            };
        }

        if (phase == QuicTlsTranscriptPhase.Failed)
        {
            return BuildFatalStep();
        }

        if (partialTranscript.WrittenCount == 0)
        {
            return new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None);
        }

        return TryAdvanceTranscript(out QuicTlsTranscriptStep step) switch
        {
            TranscriptAdvanceResult.NeedMore => new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None),
            TranscriptAdvanceResult.Progressed => step,
            TranscriptAdvanceResult.Failed => BuildFatalStep(),
            _ => new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None),
        };
    }

    internal static bool TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = 0;

        Span<byte> encodedTransportParameters = stackalloc byte[512];
        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            encodedTransportParameters,
            out int encodedTransportParametersBytes))
        {
            return false;
        }

        int extensionLength = checked(UInt16Length + encodedTransportParametersBytes);
        int extensionsLength = checked(UInt16Length + extensionLength);
        int messageBodyLength = checked(UInt16Length + extensionsLength);
        int totalMessageLength = checked(HandshakeHeaderLength + messageBodyLength);
        if (destination.Length < totalMessageLength)
        {
            return false;
        }

        destination[0] = (byte)QuicTlsHandshakeMessageType.EncryptedExtensions;
        WriteUInt24(destination.Slice(1, UInt24Length), messageBodyLength);
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.Slice(HandshakeHeaderLength, UInt16Length),
            checked((ushort)extensionsLength));
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.Slice(HandshakeHeaderLength + UInt16Length, UInt16Length),
            QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.Slice(HandshakeHeaderLength + UInt16Length + UInt16Length, UInt16Length),
            checked((ushort)encodedTransportParametersBytes));
        encodedTransportParameters[..encodedTransportParametersBytes].CopyTo(destination[(HandshakeHeaderLength + UInt16Length + UInt16Length + UInt16Length)..]);

        bytesWritten = totalMessageLength;
        return true;
    }

    private TranscriptAdvanceResult TryAdvanceTranscript(out QuicTlsTranscriptStep step)
    {
        step = new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None);

        ReadOnlySpan<byte> transcriptBytes = partialTranscript.WrittenSpan;
        if (transcriptBytes.Length < HandshakeHeaderLength)
        {
            return TranscriptAdvanceResult.NeedMore;
        }

        if (!TryMapHandshakeMessageType(transcriptBytes[0], out QuicTlsHandshakeMessageType messageType))
        {
            return Fail(HandshakeTranscriptParseFailureAlertDescription);
        }

        uint handshakeMessageBodyLength = ReadUInt24(transcriptBytes.Slice(1, UInt24Length));

        if (!TryGetExpectedMessageType(out QuicTlsHandshakeMessageType expectedMessageType)
            || messageType != expectedMessageType)
        {
            return Fail(HandshakeTranscriptParseFailureAlertDescription);
        }

        if (!TryGetTotalMessageLength(handshakeMessageBodyLength, out int totalMessageLength))
        {
            return Fail(HandshakeTranscriptParseFailureAlertDescription);
        }

        if (transcriptBytes.Length < totalMessageLength)
        {
            return TranscriptAdvanceResult.NeedMore;
        }

        ReadOnlySpan<byte> handshakeMessageBody = transcriptBytes.Slice(
            HandshakeHeaderLength,
            checked((int)handshakeMessageBodyLength));
        ReadOnlyMemory<byte> handshakeMessageBytes = transcriptBytes.Slice(0, totalMessageLength).ToArray();

        if (!TryParseCurrentMessage(
            messageType,
            handshakeMessageBody,
            handshakeMessageBodyLength,
            out ParsedHandshakeMessage parsedMessage))
        {
            return Fail(HandshakeTranscriptParseFailureAlertDescription);
        }

        CommitParsedMessage(parsedMessage);
        ConsumeBytes(totalMessageLength);
        step = new QuicTlsTranscriptStep(
            parsedMessage.StepKind,
            parsedMessage.TranscriptPhase,
            parsedMessage.TransportParameters,
            parsedMessage.HandshakeMessageType,
            parsedMessage.HandshakeMessageLength,
            parsedMessage.SelectedCipherSuite,
            parsedMessage.TranscriptHashAlgorithm,
            NamedGroup: parsedMessage.NamedGroup,
            KeyShare: parsedMessage.KeyShare,
            PreSharedKeySelected: parsedMessage.PreSharedKeySelected,
            EarlyDataAccepted: parsedMessage.EarlyDataAccepted,
            HandshakeMessageBytes: handshakeMessageBytes);
        return TranscriptAdvanceResult.Progressed;
    }

    private TranscriptAdvanceResult TryAdvancePostHandshakeTranscript(out QuicTlsTranscriptStep step)
    {
        step = new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None);

        while (true)
        {
            ReadOnlySpan<byte> transcriptBytes = postHandshakeTranscript.WrittenSpan;
            if (transcriptBytes.Length == 0)
            {
                return TranscriptAdvanceResult.NeedMore;
            }

            if (transcriptBytes.Length < HandshakeHeaderLength)
            {
                return TranscriptAdvanceResult.NeedMore;
            }

            uint handshakeMessageBodyLength = ReadUInt24(transcriptBytes.Slice(1, UInt24Length));
            if (!TryGetTotalMessageLength(handshakeMessageBodyLength, out int totalMessageLength))
            {
                postHandshakeTranscript.Clear();
                postHandshakeIngressCursor = 0;
                return TranscriptAdvanceResult.NeedMore;
            }

            if (transcriptBytes.Length < totalMessageLength)
            {
                return TranscriptAdvanceResult.NeedMore;
            }

            ReadOnlySpan<byte> handshakeMessageBody = transcriptBytes.Slice(
                HandshakeHeaderLength,
                checked((int)handshakeMessageBodyLength));
            QuicTlsHandshakeMessageType messageType = (QuicTlsHandshakeMessageType)transcriptBytes[0];

            if (messageType != QuicTlsHandshakeMessageType.NewSessionTicket)
            {
                ConsumePostHandshakeBytes(totalMessageLength);
                continue;
            }

            if (!TryParseNewSessionTicket(
                handshakeMessageBody,
                out uint ticketLifetimeSeconds,
                out uint ticketAgeAdd,
                out ReadOnlyMemory<byte> ticketNonce,
                out ReadOnlyMemory<byte> ticketBytes,
                out uint? ticketMaxEarlyDataSize))
            {
                ConsumePostHandshakeBytes(totalMessageLength);
                continue;
            }

            ConsumePostHandshakeBytes(totalMessageLength);
            step = new QuicTlsTranscriptStep(
                QuicTlsTranscriptStepKind.PostHandshakeTicketAvailable,
                QuicTlsTranscriptPhase.Completed,
                TicketNonce: ticketNonce,
                TicketLifetimeSeconds: ticketLifetimeSeconds,
                TicketAgeAdd: ticketAgeAdd,
                TicketMaxEarlyDataSize: ticketMaxEarlyDataSize,
                TicketBytes: ticketBytes);
            return TranscriptAdvanceResult.Progressed;
        }
    }

    private bool TryParseCurrentMessage(
        QuicTlsHandshakeMessageType messageType,
        ReadOnlySpan<byte> handshakeMessageBody,
        uint handshakeMessageLengthValue,
        out ParsedHandshakeMessage parsedMessage)
    {
        parsedMessage = default;

        return progressState switch
        {
            HandshakeProgressState.AwaitingClientHello
                => messageType == QuicTlsHandshakeMessageType.ClientHello
                    && TryParseClientHello(handshakeMessageBody, handshakeMessageLengthValue, out parsedMessage),
            HandshakeProgressState.AwaitingServerHello
                => messageType == QuicTlsHandshakeMessageType.ServerHello
                    && TryParseServerHello(handshakeMessageBody, handshakeMessageLengthValue, out parsedMessage),
            HandshakeProgressState.AwaitingEncryptedExtensions
                => messageType == QuicTlsHandshakeMessageType.EncryptedExtensions
                    && TryParseEncryptedExtensions(handshakeMessageBody, handshakeMessageLengthValue, out parsedMessage),
            HandshakeProgressState.AwaitingCertificate
                => messageType == QuicTlsHandshakeMessageType.Certificate
                    && TryParseCertificate(handshakeMessageBody, handshakeMessageLengthValue, out parsedMessage),
            HandshakeProgressState.AwaitingCertificateVerify
                => messageType == QuicTlsHandshakeMessageType.CertificateVerify
                    && TryParseCertificateVerify(handshakeMessageBody, handshakeMessageLengthValue, out parsedMessage),
            HandshakeProgressState.AwaitingFinished
                => messageType == QuicTlsHandshakeMessageType.Finished
                    && TryParseFinished(handshakeMessageBody, handshakeMessageLengthValue, out parsedMessage),
            HandshakeProgressState.Completed or HandshakeProgressState.Failed => false,
            _ => false,
        };
    }

    private bool TryParseClientHello(
        ReadOnlySpan<byte> handshakeMessageBody,
        uint handshakeMessageLengthValue,
        out ParsedHandshakeMessage parsedMessage)
    {
        parsedMessage = default;

        int index = 0;
        if (!TryReadUInt16(handshakeMessageBody, ref index, out ushort legacyVersion)
            || legacyVersion != TlsLegacyVersion
            || !TrySkipBytes(handshakeMessageBody, ref index, TlsRandomLength)
            || !TryReadUInt8(handshakeMessageBody, ref index, out int sessionIdLength)
            || sessionIdLength > MaximumSessionIdLength
            || !TrySkipBytes(handshakeMessageBody, ref index, sessionIdLength)
            || !TryReadUInt16(handshakeMessageBody, ref index, out ushort cipherSuitesLength)
            || cipherSuitesLength < 2
            || (cipherSuitesLength & 1) != 0
            || !TrySkipBytes(handshakeMessageBody, ref index, cipherSuitesLength)
            || !TryReadUInt8(handshakeMessageBody, ref index, out int compressionMethodsLength)
            || compressionMethodsLength != 1
            || !TryReadUInt8(handshakeMessageBody, ref index, out int compressionMethod)
            || compressionMethod != NullCompressionMethod
            || !TryReadUInt16(handshakeMessageBody, ref index, out ushort extensionsLength)
            || !TrySkipBytes(handshakeMessageBody, ref index, extensionsLength)
            || index != handshakeMessageBody.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> cipherSuites = handshakeMessageBody.Slice(
            2 + TlsRandomLength + 1 + sessionIdLength + UInt16Length,
            cipherSuitesLength);

        if (!TrySelectSupportedClientHelloCipherSuite(
                cipherSuites,
                out QuicTlsCipherSuite cipherSuite,
                out QuicTlsTranscriptHashAlgorithm hashAlgorithm)
            || !TryParseClientHelloExtensions(
                handshakeMessageBody.Slice(handshakeMessageBody.Length - extensionsLength, extensionsLength),
                GetTransportParameterRoleForCurrentEndpoint(),
                out QuicTlsNamedGroup peerNamedGroup,
                out ReadOnlyMemory<byte> peerKeyShare,
                out QuicTransportParameters? transportParameters))
        {
            return false;
        }

        parsedMessage = new ParsedHandshakeMessage(
            QuicTlsTranscriptStepKind.PeerTransportParametersStaged,
            QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            serverClientCertificateRequired
                ? HandshakeProgressState.AwaitingCertificate
                : HandshakeProgressState.AwaitingFinished,
            QuicTlsHandshakeMessageType.ClientHello,
            handshakeMessageLengthValue,
            transportParameters,
            cipherSuite,
            hashAlgorithm,
            peerNamedGroup,
            peerKeyShare);
        return true;
    }

    private bool TryParseServerHello(
        ReadOnlySpan<byte> handshakeMessageBody,
        uint handshakeMessageLengthValue,
        out ParsedHandshakeMessage parsedMessage)
    {
        parsedMessage = default;

        int index = 0;
        if (!TryReadUInt16(handshakeMessageBody, ref index, out ushort legacyVersion)
            || legacyVersion != TlsLegacyVersion
            || !TrySkipBytes(handshakeMessageBody, ref index, TlsRandomLength)
            || !TryReadUInt8(handshakeMessageBody, ref index, out int sessionIdLength)
            || sessionIdLength > MaximumSessionIdLength
            || !TrySkipBytes(handshakeMessageBody, ref index, sessionIdLength)
            || !TryReadUInt16(handshakeMessageBody, ref index, out ushort cipherSuiteValue)
            || !TryMapCipherSuite(
                cipherSuiteValue,
                out QuicTlsCipherSuite cipherSuite,
                out QuicTlsTranscriptHashAlgorithm hashAlgorithm)
            || !TryReadUInt8(handshakeMessageBody, ref index, out int compressionMethod)
            || compressionMethod != NullCompressionMethod
            || !TryReadUInt16(handshakeMessageBody, ref index, out ushort extensionsLength)
            || !TrySkipBytes(handshakeMessageBody, ref index, extensionsLength)
            || index != handshakeMessageBody.Length)
        {
            return false;
        }

        if (!TryParseServerHelloExtensions(
            handshakeMessageBody.Slice(handshakeMessageBody.Length - extensionsLength, extensionsLength),
            out QuicTlsNamedGroup peerNamedGroup,
            out ReadOnlyMemory<byte> peerKeyShare,
            out bool preSharedKeySelected))
        {
            return false;
        }

        parsedMessage = new ParsedHandshakeMessage(
            QuicTlsTranscriptStepKind.Progressed,
            phase,
            HandshakeProgressState.AwaitingEncryptedExtensions,
            QuicTlsHandshakeMessageType.ServerHello,
            handshakeMessageLengthValue,
            SelectedCipherSuite: cipherSuite,
            TranscriptHashAlgorithm: hashAlgorithm,
            NamedGroup: peerNamedGroup,
            KeyShare: peerKeyShare,
            PreSharedKeySelected: preSharedKeySelected);
        serverHelloSelectedPreSharedKey = preSharedKeySelected;
        return true;
    }

    private bool TryParseEncryptedExtensions(
        ReadOnlySpan<byte> handshakeMessageBody,
        uint handshakeMessageLengthValue,
        out ParsedHandshakeMessage parsedMessage)
    {
        parsedMessage = default;

        int index = 0;
        if (!TryReadUInt16(handshakeMessageBody, ref index, out ushort extensionsLength)
            || !TrySkipBytes(handshakeMessageBody, ref index, extensionsLength)
            || index != handshakeMessageBody.Length)
        {
            return false;
        }

        if (!TryParseEncryptedExtensionsTransportParameters(
            handshakeMessageBody.Slice(handshakeMessageBody.Length - extensionsLength, extensionsLength),
            allowTransportParameters: true,
            requireTransportParameters: true,
            allowEarlyDataExtension: serverHelloSelectedPreSharedKey,
            reportEarlyDataDisposition: serverHelloSelectedPreSharedKey,
            receiverRole: GetTransportParameterRoleForCurrentEndpoint(),
            out QuicTransportParameters? transportParameters,
            out bool? earlyDataAccepted))
        {
            return false;
        }

        parsedMessage = new ParsedHandshakeMessage(
            QuicTlsTranscriptStepKind.PeerTransportParametersStaged,
            QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            serverHelloSelectedPreSharedKey
                ? HandshakeProgressState.AwaitingFinished
                : HandshakeProgressState.AwaitingCertificate,
            QuicTlsHandshakeMessageType.EncryptedExtensions,
            handshakeMessageLengthValue,
            transportParameters,
            EarlyDataAccepted: earlyDataAccepted);
        return true;
    }

    private bool TryParseCertificate(
        ReadOnlySpan<byte> handshakeMessageBody,
        uint handshakeMessageLengthValue,
        out ParsedHandshakeMessage parsedMessage)
    {
        parsedMessage = default;

        int index = 0;
        if (!TryReadUInt8(handshakeMessageBody, ref index, out int certificateRequestContextLength)
            || certificateRequestContextLength != 0
            || !TrySkipBytes(handshakeMessageBody, ref index, certificateRequestContextLength)
            || !TryReadUInt24(handshakeMessageBody, ref index, out uint certificateListLength)
            || certificateListLength == 0
            || !TrySkipBytes(handshakeMessageBody, ref index, checked((int)certificateListLength))
            || index != handshakeMessageBody.Length)
        {
            return false;
        }

        parsedMessage = new ParsedHandshakeMessage(
            QuicTlsTranscriptStepKind.Progressed,
            phase,
            HandshakeProgressState.AwaitingCertificateVerify,
            QuicTlsHandshakeMessageType.Certificate,
            handshakeMessageLengthValue);
        return true;
    }

    private bool TryParseCertificateVerify(
        ReadOnlySpan<byte> handshakeMessageBody,
        uint handshakeMessageLengthValue,
        out ParsedHandshakeMessage parsedMessage)
    {
        parsedMessage = default;

        if (handshakeMessageBody.Length < CertificateVerifyMinimumLength)
        {
            return false;
        }

        parsedMessage = new ParsedHandshakeMessage(
            QuicTlsTranscriptStepKind.Progressed,
            phase,
            HandshakeProgressState.AwaitingFinished,
            QuicTlsHandshakeMessageType.CertificateVerify,
            handshakeMessageLengthValue);
        return true;
    }

    private bool TryParseFinished(
        ReadOnlySpan<byte> handshakeMessageBody,
        uint handshakeMessageLengthValue,
        out ParsedHandshakeMessage parsedMessage)
    {
        parsedMessage = default;

        if (!transcriptHashAlgorithm.HasValue)
        {
            return false;
        }

        int expectedLength = transcriptHashAlgorithm.Value switch
        {
            QuicTlsTranscriptHashAlgorithm.Sha256 => FinishedSha256Length,
            QuicTlsTranscriptHashAlgorithm.Sha384 => FinishedSha384Length,
            _ => 0,
        };

        if (expectedLength == 0 || handshakeMessageBody.Length != expectedLength)
        {
            return false;
        }

        parsedMessage = new ParsedHandshakeMessage(
            QuicTlsTranscriptStepKind.Progressed,
            QuicTlsTranscriptPhase.Completed,
            HandshakeProgressState.Completed,
            QuicTlsHandshakeMessageType.Finished,
            handshakeMessageLengthValue);
        return true;
    }

    private static bool TryParseNewSessionTicket(
        ReadOnlySpan<byte> handshakeMessageBody,
        out uint ticketLifetimeSeconds,
        out uint ticketAgeAdd,
        out ReadOnlyMemory<byte> ticketNonce,
        out ReadOnlyMemory<byte> ticketBytes,
        out uint? ticketMaxEarlyDataSize)
    {
        ticketLifetimeSeconds = 0;
        ticketAgeAdd = 0;
        ticketNonce = default;
        ticketBytes = default;
        ticketMaxEarlyDataSize = null;

        int index = 0;
        if (!TryReadUInt32(handshakeMessageBody, ref index, out ticketLifetimeSeconds)
            || !TryReadUInt32(handshakeMessageBody, ref index, out ticketAgeAdd)
            || !TryReadUInt8(handshakeMessageBody, ref index, out int ticketNonceLength)
            || !TrySkipBytes(handshakeMessageBody, ref index, ticketNonceLength)
            || !TryReadUInt16(handshakeMessageBody, ref index, out ushort ticketLength)
            || ticketLength == 0)
        {
            return false;
        }

        int ticketNonceOffset = index - ticketNonceLength - UInt16Length;
        int ticketBytesOffset = index;
        if (!TrySkipBytes(handshakeMessageBody, ref index, ticketLength)
            || !TryReadUInt16(handshakeMessageBody, ref index, out ushort extensionsLength)
            || index + extensionsLength > handshakeMessageBody.Length)
        {
            return false;
        }

        int extensionsEnd = index + extensionsLength;
        bool seenEarlyDataExtension = false;
        while (index < extensionsEnd)
        {
            if (!TryReadUInt16(handshakeMessageBody, ref index, out ushort extensionType)
                || !TryReadUInt16(handshakeMessageBody, ref index, out ushort extensionLength))
            {
                return false;
            }

            int extensionValueStart = index;
            int extensionValueEnd = extensionValueStart + extensionLength;
            if (extensionValueEnd > extensionsEnd)
            {
                return false;
            }

            if (extensionType == EarlyDataExtensionType)
            {
                if (seenEarlyDataExtension || extensionLength != sizeof(uint))
                {
                    return false;
                }

                ticketMaxEarlyDataSize = BinaryPrimitives.ReadUInt32BigEndian(handshakeMessageBody.Slice(extensionValueStart, sizeof(uint)));
                seenEarlyDataExtension = true;
            }

            index = extensionValueEnd;
        }

        if (index != extensionsEnd)
        {
            return false;
        }

        ticketNonce = handshakeMessageBody.Slice(ticketNonceOffset, ticketNonceLength).ToArray();
        ticketBytes = handshakeMessageBody.Slice(ticketBytesOffset, ticketLength).ToArray();
        return true;
    }

    private bool TryParseServerHelloExtensions(
        ReadOnlySpan<byte> extensions,
        out QuicTlsNamedGroup peerNamedGroup,
        out ReadOnlyMemory<byte> peerKeyShare,
        out bool preSharedKeySelected)
    {
        peerNamedGroup = default;
        peerKeyShare = default;
        preSharedKeySelected = false;

        bool foundSupportedVersions = false;
        bool foundKeyShare = false;
        bool foundPreSharedKey = false;
        List<ushort> seenExtensionTypes = [];

        int index = 0;
        while (index < extensions.Length)
        {
            if (!TryReadUInt16(extensions, ref index, out ushort extensionType)
                || !TryReadUInt16(extensions, ref index, out ushort extensionLength)
                || !TrySkipBytes(extensions, ref index, extensionLength))
            {
                return false;
            }

            if (seenExtensionTypes.Contains(extensionType))
            {
                return false;
            }

            seenExtensionTypes.Add(extensionType);
            ReadOnlySpan<byte> extensionValue = extensions.Slice(index - extensionLength, extensionLength);

            if (extensionType == SupportedVersionsExtensionType)
            {
                if (foundSupportedVersions || extensionLength != 2)
                {
                    return false;
                }

                int selectedVersionIndex = 0;
                if (!TryReadUInt16(extensionValue, ref selectedVersionIndex, out ushort selectedVersion)
                    || selectedVersion != Tls13Version)
                {
                    return false;
                }

                foundSupportedVersions = true;
            }
            else if (extensionType == KeyShareExtensionType)
            {
                if (foundKeyShare || !TryParseServerHelloKeyShare(extensionValue, out peerNamedGroup, out peerKeyShare))
                {
                    return false;
                }

                foundKeyShare = true;
            }
            else if (extensionType == PreSharedKeyExtensionType)
            {
                if (foundPreSharedKey
                    || !TryParseServerHelloPreSharedKey(extensionValue, out preSharedKeySelected))
                {
                    return false;
                }

                foundPreSharedKey = true;
            }
            else if (extensionType == QuicTransportParametersCodec.QuicTransportParametersExtensionType)
            {
                return false;
            }
            else
            {
                return false;
            }
        }

        return foundSupportedVersions && foundKeyShare;
    }

    private static bool TryParseServerHelloPreSharedKey(
        ReadOnlySpan<byte> extensionValue,
        out bool preSharedKeySelected)
    {
        preSharedKeySelected = false;

        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort selectedIdentity)
            || selectedIdentity != 0
            || index != extensionValue.Length)
        {
            return false;
        }

        preSharedKeySelected = true;
        return true;
    }

    private bool TryParseClientHelloExtensions(
        ReadOnlySpan<byte> extensions,
        QuicTransportParameterRole receiverRole,
        out QuicTlsNamedGroup peerNamedGroup,
        out ReadOnlyMemory<byte> peerKeyShare,
        out QuicTransportParameters? transportParameters)
    {
        peerNamedGroup = default;
        peerKeyShare = default;
        transportParameters = null;

        bool foundSupportedVersions = false;
        bool foundKeyShare = false;
        bool foundTransportParameters = false;
        bool foundPskKeyExchangeModes = false;
        bool foundPreSharedKey = false;
        List<ushort> seenExtensionTypes = [];

        int index = 0;
        while (index < extensions.Length)
        {
            if (!TryReadUInt16(extensions, ref index, out ushort extensionType)
                || !TryReadUInt16(extensions, ref index, out ushort extensionLength)
                || !TrySkipBytes(extensions, ref index, extensionLength))
            {
                return false;
            }

            if (seenExtensionTypes.Contains(extensionType))
            {
                return false;
            }

            seenExtensionTypes.Add(extensionType);
            ReadOnlySpan<byte> extensionValue = extensions.Slice(index - extensionLength, extensionLength);

            if (extensionType == SupportedVersionsExtensionType)
            {
                if (foundSupportedVersions || !TryParseClientHelloSupportedVersions(extensionValue))
                {
                    return false;
                }

                foundSupportedVersions = true;
            }
            else if (extensionType == KeyShareExtensionType)
            {
                if (foundKeyShare || !TryParseClientHelloKeyShare(extensionValue, out peerNamedGroup, out peerKeyShare))
                {
                    return false;
                }

                foundKeyShare = true;
            }
            else if (extensionType == QuicTransportParametersCodec.QuicTransportParametersExtensionType)
            {
                if (foundTransportParameters
                    || !QuicTransportParametersCodec.TryParseTransportParameters(
                        extensionValue,
                        receiverRole,
                        out QuicTransportParameters parsedTransportParameters))
                {
                    return false;
                }

                transportParameters = parsedTransportParameters;
                foundTransportParameters = true;
            }
            else if (extensionType == PskKeyExchangeModesExtensionType)
            {
                if (foundPskKeyExchangeModes || !TryParseClientHelloPskKeyExchangeModes(extensionValue))
                {
                    return false;
                }

                foundPskKeyExchangeModes = true;
            }
            else if (extensionType == PreSharedKeyExtensionType)
            {
                if (foundPreSharedKey
                    || index != extensions.Length
                    || !TryParseClientHelloPreSharedKey(extensionValue))
                {
                    return false;
                }

                foundPreSharedKey = true;
            }
            else
            {
                return false;
            }
        }

        return foundSupportedVersions
            && foundKeyShare
            && foundTransportParameters
            && foundPskKeyExchangeModes == foundPreSharedKey;
    }

    private static bool TryParseClientHelloSupportedVersions(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        if (!TryReadUInt8(extensionValue, ref index, out int versionsLength)
            || versionsLength != UInt16Length
            || index + versionsLength != extensionValue.Length)
        {
            return false;
        }

        return TryReadUInt16(extensionValue, ref index, out ushort version)
            && version == Tls13Version
            && index == extensionValue.Length;
    }

    private static bool TryParseClientHelloKeyShare(
        ReadOnlySpan<byte> extensionValue,
        out QuicTlsNamedGroup namedGroup,
        out ReadOnlyMemory<byte> peerKeyShare)
    {
        namedGroup = default;
        peerKeyShare = default;

        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort keyShareVectorLength)
            || keyShareVectorLength == 0
            || index + keyShareVectorLength != extensionValue.Length)
        {
            return false;
        }

        if (!TryReadUInt16(extensionValue, ref index, out ushort namedGroupValue)
            || namedGroupValue != Secp256r1NamedGroup
            || !TryReadUInt16(extensionValue, ref index, out ushort keyExchangeLength)
            || keyExchangeLength != Secp256r1KeyShareLength
            || !TrySkipBytes(extensionValue, ref index, keyExchangeLength)
            || index != extensionValue.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> keyExchange = extensionValue.Slice(extensionValue.Length - keyExchangeLength, keyExchangeLength);
        if (keyExchange[0] != UncompressedPointFormat)
        {
            return false;
        }

        namedGroup = QuicTlsNamedGroup.Secp256r1;
        peerKeyShare = keyExchange.ToArray();
        return true;
    }

    private static bool TryParseClientHelloPskKeyExchangeModes(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        return TryReadUInt8(extensionValue, ref index, out int modesLength)
            && modesLength == 1
            && TryReadUInt8(extensionValue, ref index, out int keyExchangeMode)
            && keyExchangeMode == PskDheKeMode
            && index == extensionValue.Length;
    }

    private static bool TryParseClientHelloPreSharedKey(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort identitiesLength)
            || identitiesLength == 0
            || index + identitiesLength > extensionValue.Length)
        {
            return false;
        }

        int identitiesEnd = index + identitiesLength;
        if (!TryReadUInt16(extensionValue, ref index, out ushort identityLength)
            || identityLength == 0
            || !TrySkipBytes(extensionValue, ref index, identityLength)
            || !TryReadUInt32(extensionValue, ref index, out _)
            || index != identitiesEnd)
        {
            return false;
        }

        if (!TryReadUInt16(extensionValue, ref index, out ushort bindersLength)
            || bindersLength != 1 + FinishedSha256Length
            || index + bindersLength != extensionValue.Length
            || !TryReadUInt8(extensionValue, ref index, out int binderLength)
            || binderLength != FinishedSha256Length
            || !TrySkipBytes(extensionValue, ref index, binderLength)
            || index != extensionValue.Length)
        {
            return false;
        }

        return true;
    }

    private static bool TryParseServerHelloKeyShare(
        ReadOnlySpan<byte> extensionValue,
        out QuicTlsNamedGroup namedGroup,
        out ReadOnlyMemory<byte> peerKeyShare)
    {
        namedGroup = default;
        peerKeyShare = default;

        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort namedGroupValue)
            || namedGroupValue != Secp256r1NamedGroup
            || !TryReadUInt16(extensionValue, ref index, out ushort keyShareLength)
            || keyShareLength != Secp256r1KeyShareLength
            || !TrySkipBytes(extensionValue, ref index, keyShareLength)
            || index != extensionValue.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> keyShareBytes = extensionValue.Slice(extensionValue.Length - keyShareLength, keyShareLength);
        if (keyShareBytes[0] != UncompressedPointFormat)
        {
            return false;
        }

        namedGroup = QuicTlsNamedGroup.Secp256r1;
        peerKeyShare = keyShareBytes.ToArray();
        return true;
    }

    private bool TryParseEncryptedExtensionsTransportParameters(
        ReadOnlySpan<byte> extensions,
        bool allowTransportParameters,
        bool requireTransportParameters,
        bool allowEarlyDataExtension,
        bool reportEarlyDataDisposition,
        QuicTransportParameterRole receiverRole,
        out QuicTransportParameters? transportParameters,
        out bool? earlyDataAccepted)
    {
        transportParameters = null;
        earlyDataAccepted = reportEarlyDataDisposition ? false : null;
        bool foundTransportParameters = false;
        bool foundEarlyData = false;
        List<ushort> seenExtensionTypes = [];

        int index = 0;
        while (index < extensions.Length)
        {
            if (!TryReadUInt16(extensions, ref index, out ushort extensionType)
                || !TryReadUInt16(extensions, ref index, out ushort extensionLength)
                || !TrySkipBytes(extensions, ref index, extensionLength))
            {
                return false;
            }

            if (seenExtensionTypes.Contains(extensionType))
            {
                return false;
            }

            seenExtensionTypes.Add(extensionType);

            ReadOnlySpan<byte> extensionValue = extensions.Slice(index - extensionLength, extensionLength);
            if (extensionType == QuicTransportParametersCodec.QuicTransportParametersExtensionType)
            {
                if (!allowTransportParameters || foundTransportParameters)
                {
                    return false;
                }

                if (!QuicTransportParametersCodec.TryParseTransportParameters(
                    extensionValue,
                    receiverRole,
                    out QuicTransportParameters parsedTransportParameters))
                {
                    return false;
                }

                transportParameters = parsedTransportParameters;
                foundTransportParameters = true;
            }
            else if (extensionType == EarlyDataExtensionType)
            {
                if (!allowEarlyDataExtension || foundEarlyData || extensionLength != 0)
                {
                    return false;
                }

                if (reportEarlyDataDisposition)
                {
                    earlyDataAccepted = true;
                }

                foundEarlyData = true;
            }
            else
            {
                return false;
            }
        }

        return !requireTransportParameters || foundTransportParameters;
    }

    private bool TryGetExpectedMessageType(out QuicTlsHandshakeMessageType expectedMessageType)
    {
        expectedMessageType = progressState switch
        {
            HandshakeProgressState.AwaitingClientHello => QuicTlsHandshakeMessageType.ClientHello,
            HandshakeProgressState.AwaitingServerHello => QuicTlsHandshakeMessageType.ServerHello,
            HandshakeProgressState.AwaitingEncryptedExtensions => QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeProgressState.AwaitingCertificate => QuicTlsHandshakeMessageType.Certificate,
            HandshakeProgressState.AwaitingCertificateVerify => QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeProgressState.AwaitingFinished => QuicTlsHandshakeMessageType.Finished,
            _ => default,
        };

        return progressState is not (HandshakeProgressState.Completed or HandshakeProgressState.Failed);
    }

    private void CommitParsedMessage(ParsedHandshakeMessage parsedMessage)
    {
        handshakeMessageType = parsedMessage.HandshakeMessageType;
        handshakeMessageLength = parsedMessage.HandshakeMessageLength;

        if ((parsedMessage.HandshakeMessageType == QuicTlsHandshakeMessageType.ServerHello
            || parsedMessage.HandshakeMessageType == QuicTlsHandshakeMessageType.ClientHello)
            && parsedMessage.SelectedCipherSuite.HasValue)
        {
            selectedCipherSuite = parsedMessage.SelectedCipherSuite;
        }

        if ((parsedMessage.HandshakeMessageType == QuicTlsHandshakeMessageType.ServerHello
            || parsedMessage.HandshakeMessageType == QuicTlsHandshakeMessageType.ClientHello)
            && parsedMessage.TranscriptHashAlgorithm.HasValue)
        {
            transcriptHashAlgorithm = parsedMessage.TranscriptHashAlgorithm;
        }

        if (parsedMessage.TransportParameters is not null)
        {
            stagedPeerTransportParameters = parsedMessage.TransportParameters;
        }

        phase = parsedMessage.TranscriptPhase;
        progressState = parsedMessage.NextProgressState;
    }

    private TranscriptAdvanceResult Fail(ushort alertDescription)
    {
        terminalAlertDescription = alertDescription;
        phase = QuicTlsTranscriptPhase.Failed;
        progressState = HandshakeProgressState.Failed;
        serverHelloSelectedPreSharedKey = false;
        partialTranscript.Clear();
        return TranscriptAdvanceResult.Failed;
    }

    private QuicTlsTranscriptStep BuildFatalStep()
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Fatal,
            AlertDescription: terminalAlertDescription ?? HandshakeTranscriptParseFailureAlertDescription);
    }

    private void ConsumeBytes(int bytesConsumed)
    {
        if (bytesConsumed <= 0)
        {
            return;
        }

        ReadOnlySpan<byte> written = partialTranscript.WrittenSpan;
        if (bytesConsumed >= written.Length)
        {
            partialTranscript.Clear();
            return;
        }

        byte[] remaining = written[bytesConsumed..].ToArray();
        partialTranscript.Clear();
        remaining.CopyTo(partialTranscript.GetSpan(remaining.Length));
        partialTranscript.Advance(remaining.Length);
    }

    private void ConsumePostHandshakeBytes(int bytesConsumed)
    {
        if (bytesConsumed <= 0)
        {
            return;
        }

        ReadOnlySpan<byte> written = postHandshakeTranscript.WrittenSpan;
        if (bytesConsumed >= written.Length)
        {
            postHandshakeTranscript.Clear();
            return;
        }

        byte[] remaining = written[bytesConsumed..].ToArray();
        postHandshakeTranscript.Clear();
        remaining.CopyTo(postHandshakeTranscript.GetSpan(remaining.Length));
        postHandshakeTranscript.Advance(remaining.Length);
    }

    private QuicTransportParameterRole GetTransportParameterRoleForCurrentEndpoint()
    {
        return role == QuicTlsRole.Client
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;
    }

    private static bool TryMapHandshakeMessageType(byte value, out QuicTlsHandshakeMessageType messageType)
    {
        messageType = (QuicTlsHandshakeMessageType)value;
        return messageType is QuicTlsHandshakeMessageType.ClientHello
            or QuicTlsHandshakeMessageType.ServerHello
            or QuicTlsHandshakeMessageType.NewSessionTicket
            or QuicTlsHandshakeMessageType.EncryptedExtensions
            or QuicTlsHandshakeMessageType.Certificate
            or QuicTlsHandshakeMessageType.CertificateVerify
            or QuicTlsHandshakeMessageType.Finished;
    }

    private static bool TryGetTotalMessageLength(uint handshakeMessageBodyLength, out int totalMessageLength)
    {
        if (handshakeMessageBodyLength > int.MaxValue - HandshakeHeaderLength)
        {
            totalMessageLength = 0;
            return false;
        }

        totalMessageLength = HandshakeHeaderLength + checked((int)handshakeMessageBodyLength);
        return true;
    }

    private static bool TryMapCipherSuite(
        ushort cipherSuiteValue,
        out QuicTlsCipherSuite cipherSuite,
        out QuicTlsTranscriptHashAlgorithm transcriptHashAlgorithmValue)
    {
        cipherSuite = (QuicTlsCipherSuite)cipherSuiteValue;
        transcriptHashAlgorithmValue = cipherSuite switch
        {
            QuicTlsCipherSuite.TlsAes128GcmSha256 => QuicTlsTranscriptHashAlgorithm.Sha256,
            _ => default,
        };

        return transcriptHashAlgorithmValue == QuicTlsTranscriptHashAlgorithm.Sha256;
    }

    private static bool TrySelectSupportedClientHelloCipherSuite(
        ReadOnlySpan<byte> cipherSuites,
        out QuicTlsCipherSuite cipherSuite,
        out QuicTlsTranscriptHashAlgorithm transcriptHashAlgorithmValue)
    {
        cipherSuite = default;
        transcriptHashAlgorithmValue = default;

        int index = 0;
        if (cipherSuites.Length != UInt16Length
            || !TryReadUInt16(cipherSuites, ref index, out ushort cipherSuiteValue)
            || cipherSuiteValue != TlsAes128GcmSha256Value
            || index != cipherSuites.Length)
        {
            return false;
        }

        cipherSuite = QuicTlsCipherSuite.TlsAes128GcmSha256;
        transcriptHashAlgorithmValue = QuicTlsTranscriptHashAlgorithm.Sha256;
        return true;
    }

    private static bool TryReadUInt8(ReadOnlySpan<byte> source, ref int index, out int value)
    {
        if (index >= source.Length)
        {
            value = 0;
            return false;
        }

        value = source[index];
        index++;
        return true;
    }

    private static bool TryReadUInt16(ReadOnlySpan<byte> source, ref int index, out ushort value)
    {
        if (index > source.Length - UInt16Length)
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(index, UInt16Length));
        index += UInt16Length;
        return true;
    }

    private static bool TryReadUInt32(ReadOnlySpan<byte> source, ref int index, out uint value)
    {
        if (index > source.Length - sizeof(uint))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(index, sizeof(uint)));
        index += sizeof(uint);
        return true;
    }

    private static bool TryReadUInt24(ReadOnlySpan<byte> source, ref int index, out uint value)
    {
        if (index > source.Length - UInt24Length)
        {
            value = 0;
            return false;
        }

        value = ReadUInt24(source.Slice(index, UInt24Length));
        index += UInt24Length;
        return true;
    }

    private static bool TrySkipBytes(ReadOnlySpan<byte> source, ref int index, int length)
    {
        if (length < 0 || index > source.Length - length)
        {
            return false;
        }

        index += length;
        return true;
    }

    private static uint ReadUInt24(ReadOnlySpan<byte> value)
    {
        return (uint)((value[0] << 16) | (value[1] << 8) | value[2]);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }

    private enum TranscriptAdvanceResult
    {
        NeedMore = 0,
        Progressed = 1,
        Failed = 2,
    }

    private enum HandshakeProgressState
    {
        AwaitingClientHello = 0,
        AwaitingServerHello = 1,
        AwaitingEncryptedExtensions = 2,
        AwaitingCertificate = 3,
        AwaitingCertificateVerify = 4,
        AwaitingFinished = 5,
        Completed = 6,
        Failed = 7,
    }

    private readonly record struct ParsedHandshakeMessage(
        QuicTlsTranscriptStepKind StepKind,
        QuicTlsTranscriptPhase TranscriptPhase,
        HandshakeProgressState NextProgressState,
        QuicTlsHandshakeMessageType HandshakeMessageType,
        uint HandshakeMessageLength,
        QuicTransportParameters? TransportParameters = null,
        QuicTlsCipherSuite? SelectedCipherSuite = null,
        QuicTlsTranscriptHashAlgorithm? TranscriptHashAlgorithm = null,
        QuicTlsNamedGroup? NamedGroup = null,
        ReadOnlyMemory<byte> KeyShare = default,
        bool PreSharedKeySelected = false,
        bool? EarlyDataAccepted = null);
}

/// <summary>
/// A transcript-progress step surfaced by the bridge driver.
/// </summary>
internal enum QuicTlsTranscriptStepKind
{
    None = 0,
    Progressed = 1,
    PeerTransportParametersStaged = 2,
    PostHandshakeTicketAvailable = 3,
    Fatal = 4,
}

/// <summary>
/// A transcript-progress step surfaced by the bridge driver.
/// </summary>
internal readonly record struct QuicTlsTranscriptStep(
    QuicTlsTranscriptStepKind Kind,
    QuicTlsTranscriptPhase? TranscriptPhase = null,
    QuicTransportParameters? TransportParameters = null,
    QuicTlsHandshakeMessageType? HandshakeMessageType = null,
    uint? HandshakeMessageLength = null,
    QuicTlsCipherSuite? SelectedCipherSuite = null,
    QuicTlsTranscriptHashAlgorithm? TranscriptHashAlgorithm = null,
    QuicTlsNamedGroup? NamedGroup = null,
    ReadOnlyMemory<byte> KeyShare = default,
    bool PreSharedKeySelected = false,
    bool? EarlyDataAccepted = null,
    ReadOnlyMemory<byte> HandshakeMessageBytes = default,
    ReadOnlyMemory<byte> TicketNonce = default,
    uint? TicketLifetimeSeconds = null,
    uint? TicketAgeAdd = null,
    uint? TicketMaxEarlyDataSize = null,
    ReadOnlyMemory<byte> TicketBytes = default,
    ushort? AlertDescription = null);

#pragma warning restore S109
