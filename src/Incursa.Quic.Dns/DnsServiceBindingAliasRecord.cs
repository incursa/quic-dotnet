// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents an RFC 9460 AliasMode SVCB record for DNS service binding resolution.
/// </summary>
public sealed class DnsServiceBindingAliasRecord
{
    private const int UInt16Octets = 2;
    private const ushort AliasModePriority = 0;

    private DnsServiceBindingAliasRecord(string ownerName, string targetName)
    {
        OwnerName = ownerName;
        TargetName = targetName;
    }

    /// <summary>
    /// Gets the owner name of the AliasMode SVCB record.
    /// </summary>
    public string OwnerName { get; }

    /// <summary>
    /// Gets the AliasMode TargetName that should be resolved next.
    /// </summary>
    public string TargetName { get; }

    /// <summary>
    /// Creates an AliasMode record from presentation-format DNS names.
    /// </summary>
    public static DnsServiceBindingAliasRecord Create(string ownerName, string targetName)
    {
        return new DnsServiceBindingAliasRecord(
            DnsServiceBindingAliasResolver.NormalizeResolutionName(ownerName, nameof(ownerName)),
            DnsServiceBindingAliasResolver.NormalizeResolutionName(targetName, nameof(targetName)));
    }

    /// <summary>
    /// Parses AliasMode SVCB RDATA into an alias record for the supplied owner name.
    /// </summary>
    public static DnsServiceBindingAliasRecord ParseAliasModeRData(string ownerName, ReadOnlySpan<byte> rdata)
    {
        if (rdata.Length < UInt16Octets + 1)
        {
            throw new ArgumentException("The SVCB AliasMode RDATA is too short for SvcPriority and TargetName.", nameof(rdata));
        }

        ushort priority = BinaryPrimitives.ReadUInt16BigEndian(rdata);
        if (priority != AliasModePriority)
        {
            throw new ArgumentException("Only priority-zero AliasMode SVCB RDATA can be parsed as an alias record.", nameof(rdata));
        }

        int offset = UInt16Octets;
        string targetName = DnsServiceBindingWireRecord.ReadUncompressedDomainName(rdata, ref offset);
        if (offset != rdata.Length)
        {
            throw new ArgumentException("AliasMode SVCB RDATA must not contain SvcParams.", nameof(rdata));
        }

        return Create(ownerName, targetName);
    }
}
