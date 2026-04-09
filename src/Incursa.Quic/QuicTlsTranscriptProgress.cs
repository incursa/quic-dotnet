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
    private const byte NullCompressionMethod = 0x00;
    private const int MaximumSessionIdLength = 32;

    private readonly QuicTlsRole role;
    private readonly ArrayBufferWriter<byte> partialTranscript = new();

    private ulong ingressCursor;
    private HandshakeProgressState progressState;
    private QuicTlsTranscriptPhase phase = QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage;
    private QuicTransportParameters? stagedPeerTransportParameters;
    private QuicTlsHandshakeMessageType? handshakeMessageType;
    private uint? handshakeMessageLength;
    private QuicTlsCipherSuite? selectedCipherSuite;
    private QuicTlsTranscriptHashAlgorithm? transcriptHashAlgorithm;
    private ushort? terminalAlertDescription;

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

            return new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None);
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

    internal bool MarkPeerTransportParametersAuthenticated()
    {
        if (phase != QuicTlsTranscriptPhase.PeerTransportParametersStaged
            || stagedPeerTransportParameters is null
            || terminalAlertDescription.HasValue)
        {
            return false;
        }

        phase = QuicTlsTranscriptPhase.Completed;
        progressState = HandshakeProgressState.Completed;
        return true;
    }

    internal static bool TryFormatDeterministicTransportParametersMessage(
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
            parsedMessage.TranscriptHashAlgorithm);
        return TranscriptAdvanceResult.Progressed;
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

        if (!TryParseExtensions(
            handshakeMessageBody.Slice(handshakeMessageBody.Length - extensionsLength, extensionsLength),
            allowTransportParameters: true,
            requireTransportParameters: true,
            GetTransportParameterRoleForCurrentEndpoint(),
            out QuicTransportParameters? transportParameters))
        {
            return false;
        }

        parsedMessage = new ParsedHandshakeMessage(
            QuicTlsTranscriptStepKind.PeerTransportParametersStaged,
            QuicTlsTranscriptPhase.Completed,
            HandshakeProgressState.Completed,
            QuicTlsHandshakeMessageType.ClientHello,
            handshakeMessageLengthValue,
            transportParameters);
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
            || !TryMapCipherSuite(cipherSuiteValue, out QuicTlsCipherSuite cipherSuite, out QuicTlsTranscriptHashAlgorithm hashAlgorithm)
            || !TryReadUInt8(handshakeMessageBody, ref index, out int compressionMethod)
            || compressionMethod != NullCompressionMethod
            || !TryReadUInt16(handshakeMessageBody, ref index, out ushort extensionsLength)
            || !TrySkipBytes(handshakeMessageBody, ref index, extensionsLength)
            || index != handshakeMessageBody.Length)
        {
            return false;
        }

        if (!TryParseExtensions(
            handshakeMessageBody.Slice(handshakeMessageBody.Length - extensionsLength, extensionsLength),
            allowTransportParameters: false,
            requireTransportParameters: false,
            GetTransportParameterRoleForCurrentEndpoint(),
            out _))
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
            TranscriptHashAlgorithm: hashAlgorithm);
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

        if (!TryParseExtensions(
            handshakeMessageBody.Slice(handshakeMessageBody.Length - extensionsLength, extensionsLength),
            allowTransportParameters: true,
            requireTransportParameters: true,
            GetTransportParameterRoleForCurrentEndpoint(),
            out QuicTransportParameters? transportParameters))
        {
            return false;
        }

        parsedMessage = new ParsedHandshakeMessage(
            QuicTlsTranscriptStepKind.PeerTransportParametersStaged,
            QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeProgressState.AwaitingCertificate,
            QuicTlsHandshakeMessageType.EncryptedExtensions,
            handshakeMessageLengthValue,
            transportParameters);
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

    private bool TryParseExtensions(
        ReadOnlySpan<byte> extensions,
        bool allowTransportParameters,
        bool requireTransportParameters,
        QuicTransportParameterRole receiverRole,
        out QuicTransportParameters? transportParameters)
    {
        transportParameters = null;
        bool foundTransportParameters = false;
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

        if (parsedMessage.SelectedCipherSuite.HasValue)
        {
            selectedCipherSuite = parsedMessage.SelectedCipherSuite;
        }

        if (parsedMessage.TranscriptHashAlgorithm.HasValue)
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
            QuicTlsCipherSuite.TlsAes256GcmSha384 => QuicTlsTranscriptHashAlgorithm.Sha384,
            QuicTlsCipherSuite.TlsChacha20Poly1305Sha256 => QuicTlsTranscriptHashAlgorithm.Sha256,
            _ => default,
        };

        return transcriptHashAlgorithmValue is QuicTlsTranscriptHashAlgorithm.Sha256
            or QuicTlsTranscriptHashAlgorithm.Sha384;
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
        QuicTlsTranscriptHashAlgorithm? TranscriptHashAlgorithm = null);
}

/// <summary>
/// A transcript-progress step surfaced by the bridge driver.
/// </summary>
internal enum QuicTlsTranscriptStepKind
{
    None = 0,
    Progressed = 1,
    PeerTransportParametersStaged = 2,
    Fatal = 3,
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
    ushort? AlertDescription = null);

#pragma warning restore S109
