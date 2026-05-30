// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;
using System.Net.Security;

namespace Incursa.Quic.Dns;

/// <summary>
/// DNS over QUIC protocol defaults and option validation helpers.
/// </summary>
public static class DoqDefaults
{
    /// <summary>
    /// The ALPN token used to negotiate DNS over QUIC.
    /// </summary>
    public const string AlpnToken = "doq";

    /// <summary>
    /// The raw ALPN identification sequence used to negotiate DNS over QUIC.
    /// </summary>
    public static ReadOnlySpan<byte> Alpn => "doq"u8;

    /// <summary>
    /// The dedicated UDP port assigned to DNS over QUIC.
    /// </summary>
    public const int DefaultPort = 853;

    /// <summary>
    /// The suggested QUIC idle timeout for DoQ connections.
    /// </summary>
    public static readonly TimeSpan SuggestedIdleTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The default margin used to decide whether a connection is too close to its
    /// idle timeout to be safely reused.
    /// </summary>
    public static readonly TimeSpan DefaultIdleTimeoutMargin = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The default EDNS(0) padding block size in bytes. Messages are padded to the
    /// next multiple of this value. A value of 0 or 1 disables padding.
    /// The default of 128 follows RFC 8467 recommendations for encrypted transports.
    /// </summary>
    public static int PaddingBlockSize { get; set; } = 0;

    /// <summary>
    /// The UDP port that DNS over QUIC connections must not use.
    /// </summary>
    public const int ProhibitedPlainDnsPort = 53;

    private const int UInt16Length = 2;
    private const int DnsOpcodeShift = 3;
    private const int DnsOpcodeMask = 0x0F;
    private const byte DnsQrFlag = 0x80;
    private const byte DnsRcodeMask = 0xF0;
    private const int DnsRefusedRcode = 5;
    private const byte DnsFlagsHighMask = 0x0F;
    private const int DnsNotifyOpcode = 4;
    private const int DnsOptTtlSize = 4;

    /// <summary>
    /// Gets the DNS over QUIC ALPN protocol value.
    /// </summary>
    public static SslApplicationProtocol ApplicationProtocol { get; } = new(AlpnToken);

    /// <summary>
    /// Creates a DNS endpoint using the default DoQ port unless an explicit port is supplied.
    /// </summary>
    public static DnsEndPoint CreateClientEndPoint(string host, int port = DefaultPort)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new ArgumentException("A DNS over QUIC host name is required.", nameof(host));
        }

        ValidatePort(port, nameof(port));
        return new DnsEndPoint(host, port);
    }

    /// <summary>
    /// Creates a listen endpoint using the default DoQ port unless an explicit port is supplied.
    /// </summary>
    public static IPEndPoint CreateListenEndPoint(IPAddress address, int port = DefaultPort)
    {
        ArgumentNullException.ThrowIfNull(address);
        ValidatePort(port, nameof(port));
        return new IPEndPoint(address, port);
    }

    /// <summary>
    /// Ensures client options advertise DoQ and do not target the prohibited DNS port.
    /// </summary>
    public static void EnsureClientConnectionOptions(QuicClientConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        SslClientAuthenticationOptions authenticationOptions = options.ClientAuthenticationOptions
            ?? throw new ArgumentException("DoQ client authentication options are required.", nameof(options));

        authenticationOptions.ApplicationProtocols ??= [];
        EnsureApplicationProtocol(authenticationOptions.ApplicationProtocols, nameof(options));
        ValidateEndPointPort(options.RemoteEndPoint, nameof(options));
    }

    /// <summary>
    /// Ensures listener options advertise DoQ and do not bind the prohibited DNS port.
    /// </summary>
    public static void EnsureListenerOptions(QuicListenerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.ApplicationProtocols ??= [];
        EnsureApplicationProtocol(options.ApplicationProtocols, nameof(options));
        ValidateEndPointPort(options.ListenEndPoint, nameof(options));
    }

    /// <summary>
    /// Returns a value indicating whether the port is permitted for DoQ use.
    /// </summary>
    public static bool IsAllowedPort(int port)
        => port is >= IPEndPoint.MinPort and <= IPEndPoint.MaxPort and not ProhibitedPlainDnsPort;

    /// <summary>
    /// Returns a value indicating whether the DNS OPCODE is replayable in 0-RTT.
    /// Per RFC 9250 section 4.5, OPCODE 0 (QUERY) and 4 (NOTIFY) are replayable.
    /// All other OPCODE values are non-replayable.
    /// </summary>
    public static bool IsReplayableOpcode(int opcode)
        => opcode is 0 or DnsNotifyOpcode;

    /// <summary>
    /// Returns a value indicating whether the DNS OPCODE in the given message payload
    /// (without the DoQ length prefix) is replayable in 0-RTT.
    /// </summary>
    public static bool IsReplayableQuery(ReadOnlySpan<byte> dnsMessage)
    {
        const int MinimumDnsHeaderLength = 3;

        if (dnsMessage.Length < MinimumDnsHeaderLength)
        {
            return false;
        }

        int opcode = (dnsMessage[2] >> DnsOpcodeShift) & DnsOpcodeMask;
        return IsReplayableOpcode(opcode);
    }

    /// <summary>
    /// Builds a DNS REFUSED response with an Extended DNS Error (EDE) "Too Early" option (code 20)
    /// for the given query payload. Returns the response payload without the DoQ length prefix.
    /// </summary>
    public static byte[] BuildRefusedWithTooEarlyResponse(ReadOnlySpan<byte> queryPayload)
    {
        const int edeTooEarlyOptionCode = 20;
        const int DnsHeaderLength = 12;
        const int OptRecordType = 41;
        const int DnsAncountMsbOffset = 6;
        const int DnsNscountMsbOffset = 8;
        const int DnsArcountMsbOffset = 10;
        const int DnsQuestionFixedSize = 4;
        const int EdnsRdataLength = 6;
        const int DnsQdcountOffset = 4;
        const int DnsFlagsByteHigh = 2;
        const int DnsFlagsByteLow = 3;

        if (queryPayload.Length < DnsHeaderLength)
        {
            throw new ArgumentException("A DNS query must contain at least the 12-octet header.", nameof(queryPayload));
        }

        int qdcount = BinaryPrimitives.ReadUInt16BigEndian(queryPayload[DnsQdcountOffset..DnsAncountMsbOffset]);
        int offset = DnsHeaderLength;
        for (int i = 0; i < qdcount && offset < queryPayload.Length; i++)
        {
            if (!SkipDnsLabel(queryPayload, ref offset))
            {
                throw new InvalidOperationException("Failed to parse DNS question section.");
            }

            offset += DnsQuestionFixedSize;
        }

        int questionEnd = offset;

        int optFixedHeader = 1 + UInt16Length + UInt16Length + DnsOptTtlSize + UInt16Length;
        int ednsOptionSize = UInt16Length + UInt16Length + 2;
        int optRecordLength = optFixedHeader + ednsOptionSize;
        byte[] response = new byte[questionEnd + optRecordLength];

        queryPayload[..questionEnd].CopyTo(response);

        response[DnsFlagsByteHigh] = (byte)((response[DnsFlagsByteHigh] & DnsFlagsHighMask) | DnsQrFlag);
        response[DnsFlagsByteLow] = (byte)((response[DnsFlagsByteLow] & DnsRcodeMask) | DnsRefusedRcode);
        response[DnsAncountMsbOffset] = 0;
        response[DnsAncountMsbOffset + 1] = 0;
        response[DnsNscountMsbOffset] = 0;
        response[DnsNscountMsbOffset + 1] = 0;
        response[DnsArcountMsbOffset] = 0;
        response[DnsArcountMsbOffset + 1] = 1;

        offset = questionEnd;
        response[offset] = 0; offset++;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, UInt16Length), OptRecordType);
        offset += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, UInt16Length), 0);
        offset += UInt16Length;
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset, DnsOptTtlSize), 0);
        offset += DnsOptTtlSize;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, UInt16Length), EdnsRdataLength);
        offset += UInt16Length;
        WriteEdnsOption(response, ref offset, edeTooEarlyOptionCode, [0x00, 0x00]);

        return response;
    }

    private static void WriteEdnsOption(byte[] destination, ref int offset, int optionCode, byte[] optionData)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(offset, UInt16Length), checked((ushort)optionCode));
        offset += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(offset, UInt16Length), checked((ushort)optionData.Length));
        offset += UInt16Length;
        optionData.CopyTo(destination.AsSpan(offset));
        offset += optionData.Length;
    }

    private static bool SkipDnsLabel(ReadOnlySpan<byte> dnsMessage, ref int offset)
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
    /// Ensures the QUIC idle timeout is set on the client connection options.
    /// If the options do not specify an idle timeout, the suggested default is applied.
    /// </summary>
    public static void EnsureIdleTimeout(QuicClientConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.IdleTimeout == TimeSpan.Zero || options.IdleTimeout == System.Threading.Timeout.InfiniteTimeSpan)
        {
            options.IdleTimeout = SuggestedIdleTimeout;
        }
    }

    private static void EnsureApplicationProtocol(IList<SslApplicationProtocol> protocols, string argumentName)
    {
        if (protocols.Count == 0)
        {
            protocols.Add(ApplicationProtocol);
            return;
        }

        foreach (SslApplicationProtocol protocol in protocols)
        {
            if (protocol.Equals(ApplicationProtocol))
            {
                return;
            }
        }

        throw new ArgumentException("DNS over QUIC requires ALPN doq.", argumentName);
    }

    private static void ValidateEndPointPort(EndPoint? endpoint, string argumentName)
    {
        if (endpoint is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        int? port = endpoint switch
        {
            IPEndPoint ipEndPoint => ipEndPoint.Port,
            DnsEndPoint dnsEndPoint => dnsEndPoint.Port,
            _ => null,
        };

        if (port.HasValue)
        {
            ValidatePort(port.Value, argumentName);
        }
    }

    private static void ValidatePort(int port, string argumentName)
    {
        if (!IsAllowedPort(port))
        {
            throw new ArgumentOutOfRangeException(argumentName, port, "DNS over QUIC must use a UDP port other than 53.");
        }
    }
}
