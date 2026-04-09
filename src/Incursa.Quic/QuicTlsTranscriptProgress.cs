using System.Buffers;
using System.Buffers.Binary;

#pragma warning disable S109

namespace Incursa.Quic;

/// <summary>
/// Owns the narrow Handshake transcript progression boundary behind the TLS bridge.
/// </summary>
internal sealed class QuicTlsTranscriptProgress
{
    private const ushort HandshakeTranscriptUnavailableAlertDescription = 0x0010;
    private const ushort HandshakeTranscriptParseFailureAlertDescription = 0x0032;
    private const ushort EncryptedExtensionsHandshakeType = 0x08;
    private const int HandshakeHeaderLength = 4;
    private const int ExtensionsLengthFieldLength = 2;
    private const int ExtensionHeaderLength = 4;
    private const int EncryptedExtensionsHeaderLength = 10;
    private const int MinimumEncryptedExtensionsBodyLength = 6;
    private const int UInt24Length = 3;
    private const int UInt16BitShift = 16;
    private const int UInt8BitShift = 8;
    private const int MessageTypeOffset = 0;
    private const int MessageLengthOffset = 1;
    private const int ExtensionBlockLengthOffset = 4;
    private const int ExtensionTypeOffset = 6;
    private const int ExtensionLengthOffset = 8;

    private readonly ArrayBufferWriter<byte> partialTranscript = new();

    private ulong ingressCursor;
    private QuicTlsTranscriptPhase phase = QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage;
    private QuicTlsTranscriptParseStage parseStage = QuicTlsTranscriptParseStage.HandshakeType;
    private uint handshakeMessageBodyLength;
    private ushort extensionBlockLength;
    private ushort extensionLength;
    private QuicTransportParameters? stagedPeerTransportParameters;
    private ushort? terminalAlertDescription;

    /// <summary>
    /// Gets the number of transcript bytes accepted in order.
    /// </summary>
    internal ulong IngressCursor => ingressCursor;

    /// <summary>
    /// Gets the current transcript phase.
    /// </summary>
    internal QuicTlsTranscriptPhase Phase => phase;

    /// <summary>
    /// Gets the staged peer transport parameters, if the transcript has completed but has not been emitted yet.
    /// </summary>
    internal QuicTransportParameters? StagedPeerTransportParameters => stagedPeerTransportParameters;

    /// <summary>
    /// Gets the terminal alert description, if one has been latched.
    /// </summary>
    internal ushort? TerminalAlertDescription => terminalAlertDescription;

    /// <summary>
    /// Gets whether the transcript hit a terminal failure.
    /// </summary>
    internal bool IsTerminalFailure => terminalAlertDescription.HasValue;

    /// <summary>
    /// Gets whether the transcript still holds partial bytes internally.
    /// </summary>
    internal bool HasPendingBytes => partialTranscript.WrittenCount > 0;

    /// <summary>
    /// Appends ordered Handshake CRYPTO bytes to the transcript buffer.
    /// </summary>
    internal void AppendCryptoBytes(ulong offset, ReadOnlySpan<byte> cryptoBytes)
    {
        if (terminalAlertDescription.HasValue || cryptoBytes.IsEmpty)
        {
            return;
        }

        if (phase is QuicTlsTranscriptPhase.PeerTransportParametersStaged
            or QuicTlsTranscriptPhase.Completed
            or QuicTlsTranscriptPhase.Failed)
        {
            terminalAlertDescription = HandshakeTranscriptUnavailableAlertDescription;
            phase = QuicTlsTranscriptPhase.Failed;
            parseStage = QuicTlsTranscriptParseStage.Failed;
            return;
        }

        if (offset != ingressCursor)
        {
            terminalAlertDescription = HandshakeTranscriptParseFailureAlertDescription;
            phase = QuicTlsTranscriptPhase.Failed;
            parseStage = QuicTlsTranscriptParseStage.Failed;
            return;
        }

        Span<byte> destination = partialTranscript.GetSpan(cryptoBytes.Length);
        cryptoBytes.CopyTo(destination);
        partialTranscript.Advance(cryptoBytes.Length);
        ingressCursor = SaturatingAdd(ingressCursor, (ulong)cryptoBytes.Length);
    }

    /// <summary>
    /// Advances the transcript parser and returns the next staged step, if any.
    /// </summary>
    internal QuicTlsTranscriptStep Advance(QuicTlsRole role)
    {
        if (terminalAlertDescription.HasValue)
        {
            return new QuicTlsTranscriptStep(
                QuicTlsTranscriptStepKind.Fatal,
                AlertDescription: terminalAlertDescription);
        }

        if (phase is QuicTlsTranscriptPhase.PeerTransportParametersStaged or QuicTlsTranscriptPhase.Completed)
        {
            return new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None);
        }

        return TryAdvanceTranscript(role) switch
        {
            TranscriptAdvanceResult.NeedMore => new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None),
            TranscriptAdvanceResult.Complete => new QuicTlsTranscriptStep(
                QuicTlsTranscriptStepKind.PeerTransportParametersStaged,
                TransportParameters: stagedPeerTransportParameters),
            TranscriptAdvanceResult.Failed => new QuicTlsTranscriptStep(
                QuicTlsTranscriptStepKind.Fatal,
                AlertDescription: terminalAlertDescription ?? HandshakeTranscriptParseFailureAlertDescription),
            _ => new QuicTlsTranscriptStep(QuicTlsTranscriptStepKind.None),
        };
    }

    /// <summary>
    /// Marks the staged peer transport parameters as authenticated.
    /// </summary>
    internal bool MarkPeerTransportParametersAuthenticated()
    {
        if (phase != QuicTlsTranscriptPhase.PeerTransportParametersStaged
            || stagedPeerTransportParameters is null
            || terminalAlertDescription.HasValue)
        {
            return false;
        }

        phase = QuicTlsTranscriptPhase.Completed;
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

        int extensionsLength = ExtensionHeaderLength + encodedTransportParametersBytes;
        int messageBodyLength = ExtensionsLengthFieldLength + extensionsLength;
        int totalMessageLength = HandshakeHeaderLength + messageBodyLength;
        if (destination.Length < totalMessageLength)
        {
            return false;
        }

        destination[MessageTypeOffset] = (byte)EncryptedExtensionsHandshakeType;
        WriteUInt24(destination.Slice(MessageLengthOffset, UInt24Length), messageBodyLength);
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.Slice(ExtensionBlockLengthOffset, ExtensionsLengthFieldLength),
            checked((ushort)extensionsLength));
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.Slice(ExtensionTypeOffset, ExtensionsLengthFieldLength),
            QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.Slice(ExtensionLengthOffset, ExtensionsLengthFieldLength),
            checked((ushort)encodedTransportParametersBytes));
        encodedTransportParameters[..encodedTransportParametersBytes].CopyTo(destination[EncryptedExtensionsHeaderLength..]);

        bytesWritten = totalMessageLength;
        return true;
    }

    private TranscriptAdvanceResult TryAdvanceTranscript(QuicTlsRole role)
    {
        ReadOnlySpan<byte> transcriptBytes = partialTranscript.WrittenSpan;

        while (true)
        {
            switch (parseStage)
            {
                case QuicTlsTranscriptParseStage.HandshakeType:
                    if (transcriptBytes.Length < 1)
                    {
                        return TranscriptAdvanceResult.NeedMore;
                    }

                    if (transcriptBytes[MessageTypeOffset] != EncryptedExtensionsHandshakeType)
                    {
                        return Fail(HandshakeTranscriptParseFailureAlertDescription);
                    }

                    parseStage = QuicTlsTranscriptParseStage.MessageLength;
                    continue;

                case QuicTlsTranscriptParseStage.MessageLength:
                    if (transcriptBytes.Length < HandshakeHeaderLength)
                    {
                        return TranscriptAdvanceResult.NeedMore;
                    }

                    handshakeMessageBodyLength = ReadUInt24(transcriptBytes.Slice(MessageLengthOffset, UInt24Length));
                    if (handshakeMessageBodyLength < MinimumEncryptedExtensionsBodyLength)
                    {
                        return Fail(HandshakeTranscriptParseFailureAlertDescription);
                    }

                    parseStage = QuicTlsTranscriptParseStage.ExtensionBlockLength;
                    continue;

                case QuicTlsTranscriptParseStage.ExtensionBlockLength:
                    if (transcriptBytes.Length < ExtensionTypeOffset)
                    {
                        return TranscriptAdvanceResult.NeedMore;
                    }

                    extensionBlockLength = BinaryPrimitives.ReadUInt16BigEndian(
                        transcriptBytes.Slice(ExtensionBlockLengthOffset, ExtensionsLengthFieldLength));
                    if (extensionBlockLength != handshakeMessageBodyLength - ExtensionsLengthFieldLength)
                    {
                        return Fail(HandshakeTranscriptParseFailureAlertDescription);
                    }

                    parseStage = QuicTlsTranscriptParseStage.ExtensionHeader;
                    continue;

                case QuicTlsTranscriptParseStage.ExtensionHeader:
                    if (transcriptBytes.Length < EncryptedExtensionsHeaderLength)
                    {
                        return TranscriptAdvanceResult.NeedMore;
                    }

                    if (BinaryPrimitives.ReadUInt16BigEndian(
                        transcriptBytes.Slice(ExtensionTypeOffset, ExtensionsLengthFieldLength))
                        != QuicTransportParametersCodec.QuicTransportParametersExtensionType)
                    {
                        return Fail(HandshakeTranscriptParseFailureAlertDescription);
                    }

                    extensionLength = BinaryPrimitives.ReadUInt16BigEndian(
                        transcriptBytes.Slice(ExtensionLengthOffset, ExtensionsLengthFieldLength));
                    if (extensionBlockLength != extensionLength + ExtensionHeaderLength)
                    {
                        return Fail(HandshakeTranscriptParseFailureAlertDescription);
                    }

                    parseStage = QuicTlsTranscriptParseStage.TransportParameters;
                    continue;

                case QuicTlsTranscriptParseStage.TransportParameters:
                {
                    int expectedTranscriptLength = EncryptedExtensionsHeaderLength + extensionLength;
                    if (transcriptBytes.Length < expectedTranscriptLength)
                    {
                        return TranscriptAdvanceResult.NeedMore;
                    }

                    if (transcriptBytes.Length != expectedTranscriptLength)
                    {
                        return Fail(HandshakeTranscriptUnavailableAlertDescription);
                    }

                    ReadOnlySpan<byte> encodedTransportParameters = transcriptBytes.Slice(
                        EncryptedExtensionsHeaderLength,
                        extensionLength);
                    if (!QuicTransportParametersCodec.TryParseTransportParameters(
                            encodedTransportParameters,
                            role == QuicTlsRole.Client
                                ? QuicTransportParameterRole.Client
                                : QuicTransportParameterRole.Server,
                            out QuicTransportParameters parsedTransportParameters))
                    {
                        return Fail(HandshakeTranscriptParseFailureAlertDescription);
                    }

                    stagedPeerTransportParameters = parsedTransportParameters;
                    phase = QuicTlsTranscriptPhase.PeerTransportParametersStaged;
                    parseStage = QuicTlsTranscriptParseStage.Completed;
                    return TranscriptAdvanceResult.Complete;
                }

                case QuicTlsTranscriptParseStage.Completed:
                    return TranscriptAdvanceResult.Complete;

                case QuicTlsTranscriptParseStage.Failed:
                    return TranscriptAdvanceResult.Failed;

                default:
                    return Fail(HandshakeTranscriptParseFailureAlertDescription);
            }
        }
    }

    private TranscriptAdvanceResult Fail(ushort alertDescription)
    {
        terminalAlertDescription = alertDescription;
        phase = QuicTlsTranscriptPhase.Failed;
        parseStage = QuicTlsTranscriptParseStage.Failed;
        return TranscriptAdvanceResult.Failed;
    }

    private static uint ReadUInt24(ReadOnlySpan<byte> value)
    {
        return (uint)((value[0] << UInt16BitShift) | (value[1] << UInt8BitShift) | value[UInt24Length - 1]);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> UInt16BitShift);
        destination[1] = (byte)(value >> UInt8BitShift);
        destination[UInt24Length - 1] = (byte)value;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }

    private enum TranscriptAdvanceResult
    {
        NeedMore = 0,
        Complete = 1,
        Failed = 2,
    }

    private enum QuicTlsTranscriptParseStage
    {
        HandshakeType = 0,
        MessageLength = 1,
        ExtensionBlockLength = 2,
        ExtensionHeader = 3,
        TransportParameters = 4,
        Completed = 5,
        Failed = 6,
    }
}

/// <summary>
/// A transcript-progress step surfaced by the bridge driver.
/// </summary>
internal enum QuicTlsTranscriptStepKind
{
    None = 0,
    PeerTransportParametersStaged = 1,
    Fatal = 2,
}

/// <summary>
/// A transcript-progress step surfaced by the bridge driver.
/// </summary>
internal readonly record struct QuicTlsTranscriptStep(
    QuicTlsTranscriptStepKind Kind,
    QuicTransportParameters? TransportParameters = null,
    ushort? AlertDescription = null);

#pragma warning restore S109
