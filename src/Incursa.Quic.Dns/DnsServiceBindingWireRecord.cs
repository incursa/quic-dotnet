// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Text;

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents a parsed RFC 9461 DNS ServiceMode SVCB RDATA value.
/// </summary>
public sealed class DnsServiceBindingWireRecord
{
    private const int UInt16Octets = 2;
    private const ushort AliasModePriority = 0;
    private const ushort AlpnSvcParamKey = 1;
    private const int MaximumDomainNameOctets = 255;
    private const int MaximumLabelOctets = 63;
    private const byte DnsCompressionPointerMask = 0xC0;

    private DnsServiceBindingWireRecord(
        ushort priority,
        string targetName,
        DnsServiceBindingRecord serviceBinding,
        ReadOnlyCollection<DnsServiceBindingServiceParameter> serviceParameters)
    {
        Priority = priority;
        TargetName = targetName;
        ServiceBinding = serviceBinding;
        ServiceParameters = serviceParameters;
    }

    /// <summary>
    /// Gets the ServiceMode SvcPriority value.
    /// </summary>
    public ushort Priority { get; }

    /// <summary>
    /// Gets the uncompressed fully qualified TargetName from the SVCB RDATA.
    /// </summary>
    public string TargetName { get; }

    /// <summary>
    /// Gets scalar RFC 9461 values used by endpoint selection.
    /// </summary>
    public DnsServiceBindingRecord ServiceBinding { get; }

    /// <summary>
    /// Gets the raw SvcParams in strictly increasing key order.
    /// </summary>
    public IReadOnlyList<DnsServiceBindingServiceParameter> ServiceParameters { get; }

    /// <summary>
    /// Parses ServiceMode SVCB RDATA into DNS service binding values.
    /// </summary>
    public static DnsServiceBindingWireRecord ParseServiceModeRData(string authenticationName, ReadOnlySpan<byte> rdata)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationName);
        if (rdata.Length < UInt16Octets + 1)
        {
            throw new ArgumentException("The SVCB RDATA is too short for SvcPriority and TargetName.", nameof(rdata));
        }

        ushort priority = BinaryPrimitives.ReadUInt16BigEndian(rdata);
        if (priority == AliasModePriority)
        {
            throw new ArgumentException("AliasMode SVCB records are outside this RFC 9461 ServiceMode parser.", nameof(rdata));
        }

        int offset = UInt16Octets;
        string targetName = ReadUncompressedDomainName(rdata, ref offset);
        ReadOnlyCollection<DnsServiceBindingServiceParameter> serviceParameters =
            DnsServiceBindingServiceParameter.DecodeMany(rdata[offset..]);

        List<string> alpnProtocols = [];
        string? dohPathTemplate = null;
        int? port = null;
        Dictionary<string, string> httpsServiceParameters = new(StringComparer.OrdinalIgnoreCase);

        foreach (DnsServiceBindingServiceParameter parameter in serviceParameters)
        {
            ReadOnlySpan<byte> value = parameter.Value.Span;
            switch (parameter.Key)
            {
                case AlpnSvcParamKey:
                    alpnProtocols.AddRange(ParseAlpnValue(value));
                    break;
                case DnsServiceBindingRecord.PortSvcParamKey:
                    port = ParsePortValue(value);
                    break;
                case DnsServiceBindingRecord.DohPathSvcParamKey:
                    dohPathTemplate = ParseDohPathValue(value);
                    break;
                default:
                    httpsServiceParameters["key" + parameter.Key.ToString("D5", System.Globalization.CultureInfo.InvariantCulture)] =
                        Convert.ToHexString(value);
                    break;
            }
        }

        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            authenticationName,
            alpnProtocols,
            dohPathTemplate,
            port,
            httpsServiceParameters: httpsServiceParameters);

        return new DnsServiceBindingWireRecord(priority, targetName, record, serviceParameters);
    }

    internal static string ReadUncompressedDomainName(ReadOnlySpan<byte> source, ref int offset)
    {
        int start = offset;
        List<string> labels = [];
        while (true)
        {
            if (offset >= source.Length)
            {
                throw new ArgumentException("The SVCB TargetName is truncated.", nameof(source));
            }

            byte length = source[offset++];
            if ((length & DnsCompressionPointerMask) != 0)
            {
                throw new ArgumentException("The SVCB TargetName must be uncompressed.", nameof(source));
            }

            if (length == 0)
            {
                break;
            }

            if (length > MaximumLabelOctets || source.Length - offset < length)
            {
                throw new ArgumentException("The SVCB TargetName label is malformed or truncated.", nameof(source));
            }

            labels.Add(Encoding.ASCII.GetString(source.Slice(offset, length)).ToLowerInvariant());
            offset += length;
        }

        if (offset - start > MaximumDomainNameOctets)
        {
            throw new ArgumentException("The SVCB TargetName exceeds the DNS wire-format length limit.", nameof(source));
        }

        return labels.Count == 0 ? "." : string.Join('.', labels) + ".";
    }

    private static IEnumerable<string> ParseAlpnValue(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("The alpn SvcParamValue must contain at least one ALPN identifier.", nameof(value));
        }

        List<string> protocols = [];
        int offset = 0;
        while (offset < value.Length)
        {
            int length = value[offset++];
            if (length == 0 || value.Length - offset < length)
            {
                throw new ArgumentException("The alpn SvcParamValue contains a malformed ALPN identifier.", nameof(value));
            }

            protocols.Add(Encoding.ASCII.GetString(value.Slice(offset, length)).ToLowerInvariant());
            offset += length;
        }

        return protocols;
    }

    private static int ParsePortValue(ReadOnlySpan<byte> value)
    {
        if (value.Length != UInt16Octets)
        {
            throw new ArgumentException("The port SvcParamValue must be exactly two octets.", nameof(value));
        }

        return BinaryPrimitives.ReadUInt16BigEndian(value);
    }

    private static string ParseDohPathValue(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("The dohpath SvcParamValue must not be empty.", nameof(value));
        }

        return Encoding.UTF8.GetString(value);
    }
}
