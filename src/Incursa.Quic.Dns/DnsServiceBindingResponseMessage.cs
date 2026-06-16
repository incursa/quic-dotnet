// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Parses DNS response messages for RFC 9461 DNS service binding records and Additional-section addresses.
/// </summary>
public sealed class DnsServiceBindingResponseMessage
{
    private const int DnsHeaderLength = 12;
    private const int DnsQuestionTrailerLength = 4;
    private const int DnsResourceRecordTrailerLength = 10;
    private const int DnsTypeOffset = 0;
    private const int DnsClassOffset = 2;
    private const int DnsTtlOffset = 4;
    private const int DnsRdLengthOffset = 8;
    private const int DnsPointerMask = 0xC0;
    private const int DnsPointerValueMask = 0x3FFF;
    private const int MaximumDnsNameOctets = 255;
    private const int MaximumDnsLabelOctets = 63;
    private const int MaximumCompressionJumps = 32;
    private const ushort InternetClass = 1;
    private const ushort ARecordType = 1;
    private const ushort AaaaRecordType = 28;
    private const int ARecordAddressOctets = 4;
    private const int AaaaRecordAddressOctets = 16;

    private DnsServiceBindingResponseMessage(
        ushort messageId,
        ushort flags,
        IReadOnlyList<DnsServiceBindingQuestion> questions,
        IReadOnlyList<DnsServiceBindingAliasRecord> aliasRecords,
        IReadOnlyList<DnsServiceBindingNamedRecord> serviceRecords,
        IReadOnlyList<DnsServiceBindingAdditionalAddress> additionalAddresses)
    {
        MessageId = messageId;
        Flags = flags;
        Questions = new ReadOnlyCollection<DnsServiceBindingQuestion>([.. questions]);
        AliasRecords = new ReadOnlyCollection<DnsServiceBindingAliasRecord>([.. aliasRecords]);
        ServiceRecords = new ReadOnlyCollection<DnsServiceBindingNamedRecord>([.. serviceRecords]);
        AdditionalAddresses = new ReadOnlyCollection<DnsServiceBindingAdditionalAddress>([.. additionalAddresses]);
    }

    /// <summary>
    /// Gets the DNS message identifier.
    /// </summary>
    public ushort MessageId { get; }

    /// <summary>
    /// Gets the DNS header flags.
    /// </summary>
    public ushort Flags { get; }

    /// <summary>
    /// Gets the parsed DNS questions.
    /// </summary>
    public IReadOnlyList<DnsServiceBindingQuestion> Questions { get; }

    /// <summary>
    /// Gets AliasMode SVCB records from the answer section.
    /// </summary>
    public IReadOnlyList<DnsServiceBindingAliasRecord> AliasRecords { get; }

    /// <summary>
    /// Gets ServiceMode SVCB records from the answer section.
    /// </summary>
    public IReadOnlyList<DnsServiceBindingNamedRecord> ServiceRecords { get; }

    /// <summary>
    /// Gets A and AAAA address records from the Additional section.
    /// </summary>
    public IReadOnlyList<DnsServiceBindingAdditionalAddress> AdditionalAddresses { get; }

    /// <summary>
    /// Parses a DNS response message containing DNS service binding records.
    /// </summary>
    public static DnsServiceBindingResponseMessage Parse(string authenticationName, ReadOnlySpan<byte> dnsMessage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationName);
        if (dnsMessage.Length < DnsHeaderLength)
        {
            throw new ArgumentException("The DNS message is too short for the DNS header.", nameof(dnsMessage));
        }

        ushort messageId = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage);
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[2..]);
        ushort questionCount = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[4..]);
        ushort answerCount = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[6..]);
        ushort authorityCount = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[8..]);
        ushort additionalCount = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[10..]);

        int offset = DnsHeaderLength;
        List<DnsServiceBindingQuestion> questions = [];
        for (int i = 0; i < questionCount; i++)
        {
            string name = ReadDnsName(dnsMessage, ref offset);
            if (dnsMessage.Length - offset < DnsQuestionTrailerLength)
            {
                throw new ArgumentException("The DNS question is truncated.", nameof(dnsMessage));
            }

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[offset..]);
            ushort dnsClass = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(offset + DnsClassOffset)..]);
            offset += DnsQuestionTrailerLength;
            questions.Add(new DnsServiceBindingQuestion(name, type, dnsClass));
        }

        List<DnsServiceBindingAliasRecord> aliasRecords = [];
        List<DnsServiceBindingNamedRecord> serviceRecords = [];
        for (int i = 0; i < answerCount; i++)
        {
            DnsResourceRecordView record = ReadResourceRecord(dnsMessage, ref offset);
            if (record.Type != DnsServiceBindingRecord.SvcbResourceRecordType)
            {
                continue;
            }

            ReadOnlySpan<byte> rdata = dnsMessage.Slice(record.RDataOffset, record.RDataLength);
            if (rdata.Length < 2)
            {
                throw new ArgumentException("SVCB answer RDATA is too short for SvcPriority.", nameof(dnsMessage));
            }

            ushort priority = BinaryPrimitives.ReadUInt16BigEndian(rdata);
            if (priority == 0)
            {
                aliasRecords.Add(DnsServiceBindingAliasRecord.ParseAliasModeRData(record.OwnerName, rdata));
            }
            else
            {
                DnsServiceBindingWireRecord serviceRecord =
                    DnsServiceBindingWireRecord.ParseServiceModeRData(authenticationName, rdata);
                serviceRecords.Add(DnsServiceBindingNamedRecord.Create(record.OwnerName, serviceRecord));
            }
        }

        for (int i = 0; i < authorityCount; i++)
        {
            _ = ReadResourceRecord(dnsMessage, ref offset);
        }

        List<DnsServiceBindingAdditionalAddress> additionalAddresses = [];
        for (int i = 0; i < additionalCount; i++)
        {
            DnsResourceRecordView record = ReadResourceRecord(dnsMessage, ref offset);
            if (record.Class != InternetClass)
            {
                continue;
            }

            ReadOnlySpan<byte> rdata = dnsMessage.Slice(record.RDataOffset, record.RDataLength);
            if (record.Type == ARecordType)
            {
                if (rdata.Length != ARecordAddressOctets)
                {
                    throw new ArgumentException("Additional-section A records must carry exactly four address octets.", nameof(dnsMessage));
                }

                additionalAddresses.Add(new DnsServiceBindingAdditionalAddress(record.OwnerName, new IPAddress(rdata.ToArray())));
            }
            else if (record.Type == AaaaRecordType)
            {
                if (rdata.Length != AaaaRecordAddressOctets)
                {
                    throw new ArgumentException("Additional-section AAAA records must carry exactly sixteen address octets.", nameof(dnsMessage));
                }

                additionalAddresses.Add(new DnsServiceBindingAdditionalAddress(record.OwnerName, new IPAddress(rdata.ToArray())));
            }
        }

        if (offset != dnsMessage.Length)
        {
            throw new ArgumentException("The DNS message contains trailing bytes after the declared sections.", nameof(dnsMessage));
        }

        return new DnsServiceBindingResponseMessage(
            messageId,
            flags,
            questions,
            aliasRecords,
            serviceRecords,
            additionalAddresses);
    }

    private static DnsResourceRecordView ReadResourceRecord(ReadOnlySpan<byte> dnsMessage, ref int offset)
    {
        string ownerName = ReadDnsName(dnsMessage, ref offset);
        if (dnsMessage.Length - offset < DnsResourceRecordTrailerLength)
        {
            throw new ArgumentException("The DNS resource record header is truncated.", nameof(dnsMessage));
        }

        ushort type = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(offset + DnsTypeOffset)..]);
        ushort dnsClass = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(offset + DnsClassOffset)..]);
        uint ttl = BinaryPrimitives.ReadUInt32BigEndian(dnsMessage[(offset + DnsTtlOffset)..]);
        ushort rdataLength = BinaryPrimitives.ReadUInt16BigEndian(dnsMessage[(offset + DnsRdLengthOffset)..]);
        offset += DnsResourceRecordTrailerLength;
        if (dnsMessage.Length - offset < rdataLength)
        {
            throw new ArgumentException("The DNS resource record RDATA is truncated.", nameof(dnsMessage));
        }

        int rdataOffset = offset;
        offset += rdataLength;
        return new DnsResourceRecordView(ownerName, type, dnsClass, ttl, rdataOffset, rdataLength);
    }

    private static string ReadDnsName(ReadOnlySpan<byte> dnsMessage, ref int offset)
    {
        int originalOffset = offset;
        int currentOffset = offset;
        int consumedLength = 0;
        int jumps = 0;
        bool jumped = false;
        List<string> labels = [];

        while (true)
        {
            if ((uint)currentOffset >= (uint)dnsMessage.Length)
            {
                throw new ArgumentException("The DNS name is truncated.", nameof(dnsMessage));
            }

            byte length = dnsMessage[currentOffset++];
            if ((length & DnsPointerMask) == DnsPointerMask)
            {
                if (currentOffset >= dnsMessage.Length)
                {
                    throw new ArgumentException("The DNS compression pointer is truncated.", nameof(dnsMessage));
                }

                if (++jumps > MaximumCompressionJumps)
                {
                    throw new ArgumentException("The DNS compression pointer chain is cyclic or too deep.", nameof(dnsMessage));
                }

                int pointer = ((length << 8) | dnsMessage[currentOffset++]) & DnsPointerValueMask;
                if (pointer >= dnsMessage.Length)
                {
                    throw new ArgumentException("The DNS compression pointer points outside the message.", nameof(dnsMessage));
                }

                if (!jumped)
                {
                    consumedLength = currentOffset - originalOffset;
                    jumped = true;
                }

                currentOffset = pointer;
                continue;
            }

            if ((length & DnsPointerMask) != 0)
            {
                throw new ArgumentException("The DNS name uses a reserved label form.", nameof(dnsMessage));
            }

            if (length == 0)
            {
                if (!jumped)
                {
                    consumedLength = currentOffset - originalOffset;
                }

                break;
            }

            if (length > MaximumDnsLabelOctets || dnsMessage.Length - currentOffset < length)
            {
                throw new ArgumentException("The DNS name label is malformed or truncated.", nameof(dnsMessage));
            }

            labels.Add(System.Text.Encoding.ASCII.GetString(dnsMessage.Slice(currentOffset, length)).ToLowerInvariant());
            currentOffset += length;
        }

        if (consumedLength > MaximumDnsNameOctets)
        {
            throw new ArgumentException("The DNS name exceeds the DNS wire-format length limit.", nameof(dnsMessage));
        }

        offset = originalOffset + consumedLength;
        return labels.Count == 0 ? "." : string.Join('.', labels) + ".";
    }

    private readonly record struct DnsResourceRecordView(
        string OwnerName,
        ushort Type,
        ushort Class,
        uint Ttl,
        int RDataOffset,
        int RDataLength);
}
