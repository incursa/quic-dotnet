// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: This helper stays numeric because ingress has to validate weakly protected handshake
// payloads before frame objects exist; the explicit wire codes let it discard or process without
// allocations or extra parsing passes.
// SEE: QuicFrameCodec and QuicVariableLengthInteger
/// <summary>
/// Pure frame legality and payload-validation helpers used by the protocol ingress path.
/// </summary>
internal static class QuicPacketFrameLegality
{
    // RFC 9000 section 12.4 allows only the narrow Initial/Handshake control-frame set.
    internal const ulong HandshakePacketResetStreamFrameType = 0x04UL;
    internal const ulong HandshakePacketStopSendingFrameType = 0x05UL;
    internal const ulong HandshakePacketNewTokenFrameType = 0x07UL;
    internal const ulong HandshakePacketMaxDataFrameType = 0x10UL;
    internal const ulong HandshakePacketMaxStreamDataFrameType = 0x11UL;
    internal const ulong HandshakePacketMaxStreamsBidirectionalFrameType = 0x12UL;
    internal const ulong HandshakePacketMaxStreamsUnidirectionalFrameType = 0x13UL;
    internal const ulong HandshakePacketDataBlockedFrameType = 0x14UL;
    internal const ulong HandshakePacketStreamDataBlockedFrameType = 0x15UL;
    internal const ulong HandshakePacketStreamsBlockedBidirectionalFrameType = 0x16UL;
    internal const ulong HandshakePacketStreamsBlockedUnidirectionalFrameType = 0x17UL;
    internal const ulong HandshakePacketNewConnectionIdFrameType = 0x18UL;
    internal const ulong HandshakePacketRetireConnectionIdFrameType = 0x19UL;
    internal const ulong HandshakePacketPathChallengeFrameType = 0x1AUL;
    internal const ulong HandshakePacketPathResponseFrameType = 0x1BUL;
    internal const ulong HandshakePacketHandshakeDoneFrameType = 0x1EUL;
    internal const ulong DatagramWithoutLengthFrameType = 0x30UL;
    internal const ulong DatagramWithLengthFrameType = 0x31UL;
    internal const ulong ApplicationPacketAckFrameType = 0x02UL;
    internal const ulong ApplicationPacketCryptoFrameType = 0x06UL;

    internal static QuicWeaklyProtectedPacketPayloadValidationResult ValidateWeaklyProtectedHandshakePayload(
        ReadOnlySpan<byte> payload,
        QuicTlsEncryptionLevel encryptionLevel)
    {
        int payloadOffset = 0;
        bool observedProcessablePrefix = false;
        while (payloadOffset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[payloadOffset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                if (paddingBytesConsumed <= 0)
                {
                    return QuicWeaklyProtectedPacketPayloadValidationResult.Discard;
                }

                payloadOffset += paddingBytesConsumed;
                observedProcessablePrefix = true;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                if (pingBytesConsumed <= 0)
                {
                    return QuicWeaklyProtectedPacketPayloadValidationResult.Discard;
                }

                payloadOffset += pingBytesConsumed;
                observedProcessablePrefix = true;
                continue;
            }

            if (QuicFrameCodec.TryConsumeAckFrame(remaining, out int ackBytesConsumed))
            {
                if (ackBytesConsumed <= 0)
                {
                    return QuicWeaklyProtectedPacketPayloadValidationResult.Discard;
                }

                payloadOffset += ackBytesConsumed;
                observedProcessablePrefix = true;
                continue;
            }

            if (QuicFrameCodec.TryParseConnectionCloseFrame(
                    remaining,
                    out QuicConnectionCloseFrame connectionCloseFrame,
                    out int connectionCloseBytesConsumed))
            {
                if (connectionCloseBytesConsumed <= 0)
                {
                    return QuicWeaklyProtectedPacketPayloadValidationResult.Discard;
                }

                return connectionCloseFrame.IsApplicationError
                    ? QuicWeaklyProtectedPacketPayloadValidationResult.ConnectionError
                    : QuicWeaklyProtectedPacketPayloadValidationResult.Process;
            }

            if (QuicFrameCodec.TryParseCryptoFrame(remaining, out _, out int cryptoBytesConsumed))
            {
                if (cryptoBytesConsumed <= 0)
                {
                    return QuicWeaklyProtectedPacketPayloadValidationResult.Discard;
                }

                payloadOffset += cryptoBytesConsumed;
                observedProcessablePrefix = true;
                continue;
            }

            if (QuicVariableLengthInteger.TryParse(remaining, out ulong frameType, out int frameTypeBytesConsumed)
                && frameTypeBytesConsumed > 0
                && IsHandshakePacketForbiddenFrameType(frameType))
            {
                return encryptionLevel == QuicTlsEncryptionLevel.Handshake || observedProcessablePrefix
                    ? QuicWeaklyProtectedPacketPayloadValidationResult.ConnectionError
                    : QuicWeaklyProtectedPacketPayloadValidationResult.Discard;
            }

            return QuicWeaklyProtectedPacketPayloadValidationResult.Discard;
        }

        return QuicWeaklyProtectedPacketPayloadValidationResult.Process;
    }

    internal static bool IsHandshakePacketForbiddenFrameType(ulong frameType)
    {
        return (frameType >= QuicStreamFrameBits.StreamFrameTypeMinimum
                && frameType <= QuicStreamFrameBits.StreamFrameTypeMaximum)
            || frameType is HandshakePacketResetStreamFrameType
            || frameType is HandshakePacketStopSendingFrameType
            || frameType is HandshakePacketNewTokenFrameType
            || frameType is HandshakePacketMaxDataFrameType
            || frameType is HandshakePacketMaxStreamDataFrameType
            || frameType is HandshakePacketMaxStreamsBidirectionalFrameType
            || frameType is HandshakePacketMaxStreamsUnidirectionalFrameType
            || frameType is HandshakePacketDataBlockedFrameType
            || frameType is HandshakePacketStreamDataBlockedFrameType
            || frameType is HandshakePacketStreamsBlockedBidirectionalFrameType
            || frameType is HandshakePacketStreamsBlockedUnidirectionalFrameType
            || frameType is HandshakePacketNewConnectionIdFrameType
            || frameType is HandshakePacketRetireConnectionIdFrameType
            || frameType is HandshakePacketPathChallengeFrameType
            || frameType is HandshakePacketPathResponseFrameType
            || frameType is HandshakePacketHandshakeDoneFrameType
            || IsDatagramFrameType(frameType);
    }

    internal static bool TryReadApplicationFrameType(ReadOnlySpan<byte> payload, out ulong frameType)
    {
        return QuicVariableLengthInteger.TryParse(payload, out frameType, out int bytesConsumed)
            && bytesConsumed > 0;
    }

    internal static bool IsMaxStreamsFrameType(ulong frameType)
    {
        return frameType is HandshakePacketMaxStreamsBidirectionalFrameType
            or HandshakePacketMaxStreamsUnidirectionalFrameType;
    }

    internal static bool IsStreamsBlockedFrameType(ulong frameType)
    {
        return frameType is HandshakePacketStreamsBlockedBidirectionalFrameType
            or HandshakePacketStreamsBlockedUnidirectionalFrameType;
    }

    internal static bool IsDatagramFrameType(ulong frameType)
    {
        return frameType is DatagramWithoutLengthFrameType or DatagramWithLengthFrameType;
    }
}

internal enum QuicWeaklyProtectedPacketPayloadValidationResult
{
    Process,
    Discard,
    ConnectionError,
}
