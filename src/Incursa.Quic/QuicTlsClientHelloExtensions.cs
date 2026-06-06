// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

#pragma warning disable S109

using System.Buffers.Binary;
using System.Collections.Generic;

namespace Incursa.Quic;

// CONTEXT: This parser intentionally handles only the QUIC-relevant ClientHello extensions and
// keeps the wire lengths explicit because the transcript depends on exact byte-for-byte layout.
// SEE: TryParseClientHelloKeyShare and TryParseApplicationLayerProtocolNegotiationExtension
internal static class QuicTlsClientHelloExtensions
{
    private const int HandshakeHeaderLength = 4;
    private const int UInt16Length = sizeof(ushort);
    private const int UInt24Length = 3;
    private const int TlsRandomLength = 32;
    private const ushort TlsLegacyVersion = 0x0303;
    private const ushort ApplicationLayerProtocolNegotiationExtensionType = 0x0010;
    private const byte NullCompressionMethod = 0x00;
    private const int MaximumSessionIdLength = 32;
    private const int TlsCipherSuitesListLength = UInt16Length;
    private const ushort Secp256r1NamedGroup = (ushort)QuicTlsNamedGroup.Secp256r1;
    private const ushort X25519NamedGroup = (ushort)QuicTlsNamedGroup.X25519;
    private const int Secp256r1CoordinateLength = 32;
    private const int Secp256r1KeyShareLength = 1 + (Secp256r1CoordinateLength * 2);
    private const int X25519KeyShareLength = 32;
    private const byte UncompressedEcPointFormat = 0x00;
    private const byte UncompressedPointFormat = 0x04;
    private const int FinishedSha256Length = 32;
    private const byte PskDheKeMode = 0x01;

    internal static bool TryParseClientHelloSupportedGroups(
        ReadOnlySpan<byte> extensionValue,
        out ClientHelloSupportedGroups supportedGroups)
    {
        supportedGroups = default;

        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort groupsLength)
            || groupsLength == 0
            || (groupsLength & 1) != 0
            || index + groupsLength != extensionValue.Length)
        {
            return false;
        }

        bool foundSecp256r1 = false;
        bool foundX25519 = false;
        int groupsEnd = index + groupsLength;
        while (index < groupsEnd)
        {
            if (!TryReadUInt16(extensionValue, ref index, out ushort namedGroup))
            {
                return false;
            }

            if (namedGroup == Secp256r1NamedGroup)
            {
                if (foundSecp256r1)
                {
                    return false;
                }

                foundSecp256r1 = true;
                continue;
            }

            if (namedGroup == X25519NamedGroup)
            {
                if (foundX25519)
                {
                    return false;
                }

                foundX25519 = true;
            }
        }

        supportedGroups = new ClientHelloSupportedGroups(foundSecp256r1, foundX25519);
        return index == extensionValue.Length && (foundSecp256r1 || foundX25519);
    }

    internal static bool TryParseApplicationLayerProtocolNegotiationExtension(
        ReadOnlySpan<byte> extensionValue,
        bool requireSingleProtocol,
        bool rejectDuplicateProtocols = false)
    {
        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort protocolNameListLength)
            || protocolNameListLength == 0
            || index + protocolNameListLength != extensionValue.Length)
        {
            return false;
        }

        int protocolCount = 0;
        List<byte[]>? seenProtocols = rejectDuplicateProtocols ? [] : null;
        int protocolListEnd = index + protocolNameListLength;
        while (index < protocolListEnd)
        {
            if (!TryReadUInt8(extensionValue, ref index, out int protocolNameLength)
                || protocolNameLength == 0
                || !TrySkipBytes(extensionValue, ref index, protocolNameLength))
            {
                return false;
            }

            if (rejectDuplicateProtocols)
            {
                List<byte[]> duplicateCheckedProtocols = seenProtocols ?? [];
                seenProtocols = duplicateCheckedProtocols;
                byte[] protocolName = extensionValue.Slice(index - protocolNameLength, protocolNameLength).ToArray();
                if (ContainsProtocolName(duplicateCheckedProtocols, protocolName))
                {
                    return false;
                }

                duplicateCheckedProtocols.Add(protocolName);
            }

            protocolCount++;
        }

        return index == extensionValue.Length
            && protocolCount > 0
            && (!requireSingleProtocol || protocolCount == 1);
    }

    internal static bool TryParseClientHelloServerName(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort serverNameListLength)
            || serverNameListLength == 0
            || index + serverNameListLength != extensionValue.Length)
        {
            return false;
        }

        bool foundHostName = false;
        int serverNameListEnd = index + serverNameListLength;
        while (index < serverNameListEnd)
        {
            if (!TryReadUInt8(extensionValue, ref index, out int serverNameType)
                || serverNameType != 0
                || !TryReadUInt16(extensionValue, ref index, out ushort serverNameLength)
                || serverNameLength == 0
                || !TrySkipBytes(extensionValue, ref index, serverNameLength))
            {
                return false;
            }

            foundHostName = true;
        }

        return index == extensionValue.Length && foundHostName;
    }

    internal static bool TryParseClientHelloStatusRequest(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        if (!TryReadUInt8(extensionValue, ref index, out int statusType)
            || statusType != 1
            || !TryReadUInt16(extensionValue, ref index, out ushort responderIdListLength)
            || !TrySkipBytes(extensionValue, ref index, responderIdListLength)
            || !TryReadUInt16(extensionValue, ref index, out ushort requestExtensionsLength)
            || !TrySkipBytes(extensionValue, ref index, requestExtensionsLength))
        {
            return false;
        }

        return index == extensionValue.Length;
    }

    internal static bool TryParseClientHelloEcPointFormats(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        if (!TryReadUInt8(extensionValue, ref index, out int pointFormatsLength)
            || pointFormatsLength == 0
            || index + pointFormatsLength != extensionValue.Length)
        {
            return false;
        }

        bool foundUncompressedFormat = false;
        int pointFormatsEnd = index + pointFormatsLength;
        while (index < pointFormatsEnd)
        {
            if (!TryReadUInt8(extensionValue, ref index, out int pointFormat))
            {
                return false;
            }

            if (pointFormat == UncompressedEcPointFormat)
            {
                foundUncompressedFormat = true;
            }
        }

        return index == extensionValue.Length && foundUncompressedFormat;
    }

    internal static bool TryParseClientHelloRenegotiationInfo(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        return TryReadUInt8(extensionValue, ref index, out int renegotiatedConnectionLength)
            && renegotiatedConnectionLength == 0
            && index == extensionValue.Length;
    }

    internal static bool TryParseClientHelloKeyShare(
        ReadOnlySpan<byte> extensionValue,
        out ClientHelloKeyShareCandidates keyShareCandidates)
    {
        keyShareCandidates = default;

        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort keyShareVectorLength)
            || keyShareVectorLength == 0
            || index + keyShareVectorLength != extensionValue.Length)
        {
            return false;
        }

        bool foundUsableSecp256r1KeyShare = false;
        bool foundUsableX25519KeyShare = false;
        ReadOnlyMemory<byte> secp256r1KeyShare = default;
        ReadOnlyMemory<byte> x25519KeyShare = default;
        int keyShareVectorEnd = index + keyShareVectorLength;
        while (index < keyShareVectorEnd)
        {
            if (!TryReadUInt16(extensionValue, ref index, out ushort namedGroupValue)
                || !TryReadUInt16(extensionValue, ref index, out ushort keyExchangeLength)
                || keyExchangeLength == 0
                || !TrySkipBytes(extensionValue, ref index, keyExchangeLength))
            {
                return false;
            }

            ReadOnlySpan<byte> keyExchange = extensionValue.Slice(index - keyExchangeLength, keyExchangeLength);
            if (namedGroupValue == Secp256r1NamedGroup)
            {
                if (foundUsableSecp256r1KeyShare
                    || keyExchangeLength != Secp256r1KeyShareLength
                    || keyExchange[0] != UncompressedPointFormat)
                {
                    return false;
                }

                secp256r1KeyShare = keyExchange.ToArray();
                foundUsableSecp256r1KeyShare = true;
                continue;
            }

            if (namedGroupValue == X25519NamedGroup)
            {
                if (foundUsableX25519KeyShare || keyExchangeLength != X25519KeyShareLength)
                {
                    return false;
                }

                x25519KeyShare = keyExchange.ToArray();
                foundUsableX25519KeyShare = true;
            }
        }

        if (index != extensionValue.Length)
        {
            return false;
        }

        keyShareCandidates = new ClientHelloKeyShareCandidates(
            foundUsableSecp256r1KeyShare,
            secp256r1KeyShare,
            foundUsableX25519KeyShare,
            x25519KeyShare);
        return true;
    }

    internal static bool TryParseClientHelloPskKeyExchangeModes(ReadOnlySpan<byte> extensionValue)
    {
        int index = 0;
        if (!TryReadUInt8(extensionValue, ref index, out int modesLength)
            || modesLength == 0
            || index + modesLength != extensionValue.Length)
        {
            return false;
        }

        bool foundPskDheKe = false;
        int modesEnd = index + modesLength;
        while (index < modesEnd)
        {
            if (!TryReadUInt8(extensionValue, ref index, out int keyExchangeMode))
            {
                return false;
            }

            foundPskDheKe |= keyExchangeMode == PskDheKeMode;
        }

        return foundPskDheKe && index == extensionValue.Length;
    }

    internal static bool TryParseClientHelloPreSharedKey(ReadOnlySpan<byte> extensionValue)
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

    internal static bool TryReadClientHelloApplicationProtocols(
        ReadOnlySpan<byte> clientHelloBytes,
        out byte[][] applicationProtocols,
        out ClientHelloApplicationProtocolOfferState offerState)
    {
        applicationProtocols = [];
        offerState = ClientHelloApplicationProtocolOfferState.Missing;

        if (clientHelloBytes.Length <= HandshakeHeaderLength
            || clientHelloBytes[0] != (byte)QuicTlsHandshakeMessageType.ClientHello)
        {
            return false;
        }

        int declaredBodyLength = checked((int)ReadUInt24(clientHelloBytes.Slice(1, UInt24Length)));
        if (declaredBodyLength != clientHelloBytes.Length - HandshakeHeaderLength)
        {
            return false;
        }

        ReadOnlySpan<byte> clientHelloBody = clientHelloBytes.Slice(HandshakeHeaderLength);
        int index = 0;
        if (!TryReadUInt16(clientHelloBody, ref index, out ushort legacyVersion)
            || legacyVersion != TlsLegacyVersion
            || !TrySkipBytes(clientHelloBody, ref index, TlsRandomLength)
            || !TryReadUInt8(clientHelloBody, ref index, out int sessionIdLength)
            || sessionIdLength > MaximumSessionIdLength
            || !TrySkipBytes(clientHelloBody, ref index, sessionIdLength)
            || !TryReadUInt16(clientHelloBody, ref index, out ushort cipherSuitesLength)
            || cipherSuitesLength < TlsCipherSuitesListLength
            || (cipherSuitesLength & 1) != 0
            || !TrySkipBytes(clientHelloBody, ref index, cipherSuitesLength)
            || !TryReadUInt8(clientHelloBody, ref index, out int compressionMethodsLength)
            || compressionMethodsLength != 1
            || !TryReadUInt8(clientHelloBody, ref index, out int compressionMethod)
            || compressionMethod != NullCompressionMethod
            || !TryReadUInt16(clientHelloBody, ref index, out ushort extensionsLength)
            || !TrySkipBytes(clientHelloBody, ref index, extensionsLength)
            || index != clientHelloBody.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> extensions = clientHelloBody.Slice(clientHelloBody.Length - extensionsLength, extensionsLength);
        int extensionsIndex = 0;
        while (extensionsIndex < extensions.Length)
        {
            if (!TryReadUInt16(extensions, ref extensionsIndex, out ushort extensionType)
                || !TryReadUInt16(extensions, ref extensionsIndex, out ushort extensionLength)
                || !TrySkipBytes(extensions, ref extensionsIndex, extensionLength))
            {
                return false;
            }

            if (extensionType != ApplicationLayerProtocolNegotiationExtensionType)
            {
                continue;
            }

            if (offerState != ClientHelloApplicationProtocolOfferState.Missing)
            {
                offerState = ClientHelloApplicationProtocolOfferState.Invalid;
                return true;
            }

            if (!TryReadApplicationLayerProtocolOfferList(
                extensions.Slice(extensionsIndex - extensionLength, extensionLength),
                out applicationProtocols))
            {
                offerState = ClientHelloApplicationProtocolOfferState.Invalid;
                applicationProtocols = [];
                return true;
            }

            offerState = ClientHelloApplicationProtocolOfferState.Present;
        }

        return true;
    }

    internal static bool TryReadClientHelloTransportParameters(
        ReadOnlySpan<byte> clientHelloBytes,
        out QuicTransportParameters? transportParameters)
    {
        transportParameters = null;

        if (clientHelloBytes.Length <= HandshakeHeaderLength
            || clientHelloBytes[0] != (byte)QuicTlsHandshakeMessageType.ClientHello)
        {
            return false;
        }

        int declaredBodyLength = checked((int)ReadUInt24(clientHelloBytes.Slice(1, UInt24Length)));
        if (declaredBodyLength != clientHelloBytes.Length - HandshakeHeaderLength)
        {
            return false;
        }

        ReadOnlySpan<byte> clientHelloBody = clientHelloBytes.Slice(HandshakeHeaderLength);
        int index = 0;
        if (!TryReadUInt16(clientHelloBody, ref index, out ushort legacyVersion)
            || legacyVersion != TlsLegacyVersion
            || !TrySkipBytes(clientHelloBody, ref index, TlsRandomLength)
            || !TryReadUInt8(clientHelloBody, ref index, out int sessionIdLength)
            || sessionIdLength > MaximumSessionIdLength
            || !TrySkipBytes(clientHelloBody, ref index, sessionIdLength)
            || !TryReadUInt16(clientHelloBody, ref index, out ushort cipherSuitesLength)
            || cipherSuitesLength < TlsCipherSuitesListLength
            || (cipherSuitesLength & 1) != 0
            || !TrySkipBytes(clientHelloBody, ref index, cipherSuitesLength)
            || !TryReadUInt8(clientHelloBody, ref index, out int compressionMethodsLength)
            || compressionMethodsLength != 1
            || !TryReadUInt8(clientHelloBody, ref index, out int compressionMethod)
            || compressionMethod != NullCompressionMethod
            || !TryReadUInt16(clientHelloBody, ref index, out ushort extensionsLength)
            || !TrySkipBytes(clientHelloBody, ref index, extensionsLength)
            || index != clientHelloBody.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> extensions = clientHelloBody.Slice(clientHelloBody.Length - extensionsLength, extensionsLength);
        int extensionsIndex = 0;
        bool foundTransportParameters = false;
        while (extensionsIndex < extensions.Length)
        {
            if (!TryReadUInt16(extensions, ref extensionsIndex, out ushort extensionType)
                || !TryReadUInt16(extensions, ref extensionsIndex, out ushort extensionLength)
                || !TrySkipBytes(extensions, ref extensionsIndex, extensionLength))
            {
                return false;
            }

            if (extensionType != QuicTransportParametersCodec.QuicTransportParametersExtensionType)
            {
                continue;
            }

            if (foundTransportParameters)
            {
                return false;
            }

            foundTransportParameters = true;
            if (!QuicTransportParametersCodec.TryParseTransportParameters(
                extensions.Slice(extensionsIndex - extensionLength, extensionLength),
                QuicTransportParameterRole.Server,
                out QuicTransportParameters parsedTransportParameters))
            {
                return false;
            }

            transportParameters = parsedTransportParameters;
        }

        return true;
    }

    private static bool TryReadApplicationLayerProtocolOfferList(
        ReadOnlySpan<byte> extensionValue,
        out byte[][] applicationProtocols)
    {
        applicationProtocols = [];

        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort protocolNameListLength)
            || protocolNameListLength == 0
            || index + protocolNameListLength != extensionValue.Length)
        {
            return false;
        }

        List<byte[]> offeredProtocols = [];
        int protocolListEnd = index + protocolNameListLength;
        while (index < protocolListEnd)
        {
            if (!TryReadUInt8(extensionValue, ref index, out int protocolNameLength)
                || protocolNameLength == 0
                || !TrySkipBytes(extensionValue, ref index, protocolNameLength))
            {
                return false;
            }

            byte[] protocolName = extensionValue.Slice(index - protocolNameLength, protocolNameLength).ToArray();
            if (ContainsApplicationProtocol(offeredProtocols, protocolName))
            {
                return false;
            }

            offeredProtocols.Add(protocolName);
        }

        if (index != extensionValue.Length || offeredProtocols.Count == 0)
        {
            return false;
        }

        applicationProtocols = [.. offeredProtocols];
        return true;
    }

    private static bool ContainsProtocolName(IReadOnlyList<byte[]> seenProtocols, ReadOnlySpan<byte> protocolName)
    {
        foreach (byte[] seenProtocol in seenProtocols)
        {
            if (seenProtocol.AsSpan().SequenceEqual(protocolName))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsApplicationProtocol(IReadOnlyList<byte[]> applicationProtocols, ReadOnlySpan<byte> candidate)
    {
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            if (applicationProtocol.AsSpan().SequenceEqual(candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryReadUInt8(ReadOnlySpan<byte> source, ref int index, out int value)
    {
        if ((uint)index >= (uint)source.Length)
        {
            value = default;
            return false;
        }

        value = source[index++];
        return true;
    }

    private static bool TryReadUInt16(ReadOnlySpan<byte> source, ref int index, out ushort value)
    {
        if (index > source.Length - UInt16Length)
        {
            value = default;
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
            value = default;
            return false;
        }

        value = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(index, sizeof(uint)));
        index += sizeof(uint);
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

    private static uint ReadUInt24(ReadOnlySpan<byte> source)
    {
        return (uint)((source[0] << 16) | (source[1] << 8) | source[2]);
    }

    internal static bool TryExtractOffsetZeroInitialCryptoFrameData(
        ReadOnlySpan<byte> payload,
        out ReadOnlySpan<byte> cryptoData)
    {
        cryptoData = default;

        int payloadOffset = 0;
        while (payloadOffset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[payloadOffset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                if (paddingBytesConsumed <= 0)
                {
                    return false;
                }

                payloadOffset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryConsumeAckFrame(remaining, out int ackBytesConsumed))
            {
                if (ackBytesConsumed <= 0)
                {
                    return false;
                }

                payloadOffset += ackBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int cryptoBytesConsumed)
                || cryptoBytesConsumed <= 0)
            {
                return false;
            }

            if (cryptoFrame.Offset == 0 && !cryptoFrame.CryptoData.IsEmpty)
            {
                cryptoData = cryptoFrame.CryptoData;
                return true;
            }

            payloadOffset += cryptoBytesConsumed;
        }

        return false;
    }
}

internal readonly record struct ClientHelloSupportedGroups(
    bool HasSecp256r1,
    bool HasX25519);

internal readonly record struct ClientHelloKeyShareCandidates(
    bool HasSecp256r1,
    ReadOnlyMemory<byte> Secp256r1KeyShare,
    bool HasX25519,
    ReadOnlyMemory<byte> X25519KeyShare);

internal enum ClientHelloApplicationProtocolOfferState
{
    Missing = 0,
    Present = 1,
    Invalid = 2,
}
