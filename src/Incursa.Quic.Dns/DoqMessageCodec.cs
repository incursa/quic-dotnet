// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Dns;

/// <summary>
/// Encodes and decodes the two-octet DNS message length prefix used by DNS over QUIC.
/// </summary>
public static class DoqMessageCodec
{
    /// <summary>
    /// The number of bytes in the DoQ length prefix.
    /// </summary>
    public const int LengthPrefixSize = 2;

    /// <summary>
    /// The largest DNS message payload representable by the DoQ length prefix.
    /// </summary>
    public const int MaxPayloadLength = ushort.MaxValue;

    /// <summary>
    /// Encodes one DNS message with the two-octet length prefix.
    /// </summary>
    public static byte[] Encode(ReadOnlySpan<byte> dnsMessage)
    {
        if (dnsMessage.Length > MaxPayloadLength)
        {
            throw new ArgumentOutOfRangeException(nameof(dnsMessage), dnsMessage.Length, "A DoQ DNS message cannot exceed 65535 bytes.");
        }

        byte[] encoded = new byte[LengthPrefixSize + dnsMessage.Length];
        if (!TryEncode(dnsMessage, encoded, out _))
        {
            throw new InvalidOperationException("The DoQ message buffer was too small.");
        }

        return encoded;
    }

    /// <summary>
    /// Attempts to encode one DNS message into the supplied destination.
    /// </summary>
    public static bool TryEncode(ReadOnlySpan<byte> dnsMessage, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (dnsMessage.Length > MaxPayloadLength)
        {
            return false;
        }

        int requiredLength = LengthPrefixSize + dnsMessage.Length;
        if (destination.Length < requiredLength)
        {
            return false;
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, checked((ushort)dnsMessage.Length));
        dnsMessage.CopyTo(destination[LengthPrefixSize..]);
        bytesWritten = requiredLength;
        return true;
    }

    /// <summary>
    /// Attempts to decode one complete DoQ-framed DNS message from the supplied source.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> source, out DoqMessage message, out int bytesConsumed)
    {
        message = default;
        bytesConsumed = 0;
        if (source.Length < LengthPrefixSize)
        {
            return false;
        }

        int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(source);
        if (payloadLength > MaxPayloadLength)
        {
            return false;
        }

        int requiredLength = LengthPrefixSize + payloadLength;
        if (source.Length < requiredLength)
        {
            return false;
        }

        message = new DoqMessage(source.Slice(LengthPrefixSize, payloadLength).ToArray());
        bytesConsumed = requiredLength;
        return true;
    }

    /// <summary>
    /// Returns a value indicating whether the DNS message contains the edns-tcp-keepalive EDNS(0) option (code 11 / 0x000B).
    /// </summary>
    // CONTEXT: DoQ framing keeps the DNS payload intact apart from the 2-octet length prefix.
    // This parser walks the body just far enough to reject EDNS(0) TCP keepalive without changing
    // the underlying RFC 1035 message semantics.
    // SEE: spec:REQ-QUIC-RFC9250-0010
    // SEE: spec:REQ-QUIC-RFC9250-0053
    // SEE: spec:REQ-QUIC-RFC9250-0059
    public static bool ContainsTcpKeepaliveEdnsOption(ReadOnlySpan<byte> dnsMessage)
    {
        const int EdnsTcpKeepaliveOptionCode = 11;
        const int DnsHeaderLength = 12;
        const ushort OptRecordType = 41;
        const int DnsQuestionFixedSize = 4;
        const int DnsRecordHeaderSize = 10;
        const int RrRdlengthOffset = 8;
        const int OptRdataOffset = 10;
        const int EdnsOptionHeaderSize = 4;
        const int DnsArcountOffset = 10;
        const int DnsHdrEndOfArcount = DnsArcountOffset + LengthPrefixSize;
        const int DnsNscountOffset = 8;
        const int DnsQdcountOffset = 4;
        const int DnsAncountOffset = 6;

        if (dnsMessage.Length < DnsHeaderLength)
        {
            return false;
        }

        ushort arcount = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[DnsArcountOffset..DnsHdrEndOfArcount]);
        if (arcount == 0)
        {
            return false;
        }

        int offset = DnsHeaderLength;

        int qdcount = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[DnsQdcountOffset..DnsAncountOffset]);
        for (int i = 0; i < qdcount && offset < dnsMessage.Length; i++)
        {
            if (!SkipDnsName(dnsMessage, ref offset))
            {
                return false;
            }

            offset += DnsQuestionFixedSize;
        }

        int ancount = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[DnsAncountOffset..DnsNscountOffset]);
        for (int i = 0; i < ancount && offset < dnsMessage.Length; i++)
        {
            if (!SkipDnsName(dnsMessage, ref offset))
            {
                return false;
            }

            if (offset + RrRdlengthOffset > dnsMessage.Length)
            {
                return false;
            }

            ushort rdlength = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(offset + RrRdlengthOffset)..(offset + DnsRecordHeaderSize)]);
            offset += DnsRecordHeaderSize + rdlength;
        }

        int nscount = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[DnsNscountOffset..DnsArcountOffset]);
        for (int i = 0; i < nscount && offset < dnsMessage.Length; i++)
        {
            if (!SkipDnsName(dnsMessage, ref offset))
            {
                return false;
            }

            if (offset + RrRdlengthOffset > dnsMessage.Length)
            {
                return false;
            }

            ushort rdlength = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(offset + RrRdlengthOffset)..(offset + DnsRecordHeaderSize)]);
            offset += DnsRecordHeaderSize + rdlength;
        }

        for (int i = 0; i < arcount && offset < dnsMessage.Length; i++)
        {
            if (!SkipDnsName(dnsMessage, ref offset))
            {
                return false;
            }

            if (offset + DnsRecordHeaderSize > dnsMessage.Length)
            {
                return false;
            }

            ushort rrType = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[offset..(offset + LengthPrefixSize)]);

            if (rrType != OptRecordType)
            {
                ushort rdlength = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(offset + RrRdlengthOffset)..(offset + DnsRecordHeaderSize)]);
                offset += DnsRecordHeaderSize + rdlength;
                continue;
            }

            int optDataStart = offset + OptRdataOffset;
            if (optDataStart >= dnsMessage.Length)
            {
                return false;
            }

            ushort rdlengthOpt = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(offset + RrRdlengthOffset)..(offset + DnsRecordHeaderSize)]);
            int optDataEnd = optDataStart + rdlengthOpt;
            if (optDataEnd > dnsMessage.Length)
            {
                return false;
            }

            int optOffset = optDataStart;
            while (optOffset + EdnsOptionHeaderSize <= optDataEnd)
            {
                ushort optionCode = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[optOffset..(optOffset + LengthPrefixSize)]);
                ushort optionLength = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(optOffset + LengthPrefixSize)..(optOffset + EdnsOptionHeaderSize)]);

                if (optionCode == EdnsTcpKeepaliveOptionCode)
                {
                    return true;
                }

                optOffset += EdnsOptionHeaderSize + optionLength;
            }

            offset += DnsRecordHeaderSize + rdlengthOpt;
        }

        return false;
    }

    private static bool SkipDnsName(ReadOnlySpan<byte> dnsMessage, ref int offset)
    {
        const byte DnsPointerMask = 0xC0;
        const int DnsCompressedNameSkip = 2;

        while (offset < dnsMessage.Length && dnsMessage[offset] != 0)
        {
            byte labelLength = dnsMessage[offset];
            if ((labelLength & DnsPointerMask) == DnsPointerMask)
            {
                offset += DnsCompressedNameSkip;
                return true;
            }

            offset += 1 + labelLength;
            if (offset > dnsMessage.Length)
            {
                return false;
            }
        }

        if (offset >= dnsMessage.Length)
        {
            return false;
        }

        offset++;
        return true;
    }

    /// <summary>
    /// Decodes one complete DoQ-framed DNS message from the supplied source.
    /// </summary>
    public static DoqMessage Decode(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        if (TryDecode(source, out DoqMessage message, out bytesConsumed))
        {
            return message;
        }

        throw new DoqException(DoqErrorCode.ProtocolError, "The DoQ DNS message frame is incomplete.");
    }
}
