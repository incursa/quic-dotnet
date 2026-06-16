// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Resolves RFC 9460 AliasMode chains to RFC 9461 DNS ServiceMode records.
/// </summary>
public static class DnsServiceBindingAliasResolver
{
    private const int DefaultMaximumAliasDepth = 8;
    private const int MaximumDnsNameLength = 253;
    private const int MaximumDnsLabelLength = 63;

    /// <summary>
    /// Resolves a DNS service binding owner name through AliasMode records to ServiceMode records.
    /// </summary>
    public static DnsServiceBindingAliasResolution Resolve(
        string queryName,
        IEnumerable<DnsServiceBindingAliasRecord> aliasRecords,
        IEnumerable<DnsServiceBindingNamedRecord> serviceRecords,
        int maximumAliasDepth = DefaultMaximumAliasDepth)
    {
        string normalizedQueryName = NormalizeResolutionName(queryName, nameof(queryName));
        ArgumentNullException.ThrowIfNull(aliasRecords);
        ArgumentNullException.ThrowIfNull(serviceRecords);
        if (maximumAliasDepth < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAliasDepth), maximumAliasDepth, "The maximum alias depth must not be negative.");
        }

        Dictionary<string, DnsServiceBindingAliasRecord> aliasesByOwner = new(StringComparer.Ordinal);
        foreach (DnsServiceBindingAliasRecord aliasRecord in aliasRecords)
        {
            aliasesByOwner.TryAdd(aliasRecord.OwnerName, aliasRecord);
        }

        Dictionary<string, List<DnsServiceBindingNamedRecord>> servicesByOwner = new(StringComparer.Ordinal);
        foreach (DnsServiceBindingNamedRecord serviceRecord in serviceRecords)
        {
            if (!servicesByOwner.TryGetValue(serviceRecord.OwnerName, out List<DnsServiceBindingNamedRecord>? records))
            {
                records = [];
                servicesByOwner.Add(serviceRecord.OwnerName, records);
            }

            records.Add(serviceRecord);
        }

        List<string> aliasChain = [];
        HashSet<string> visited = new(StringComparer.Ordinal);
        string currentName = normalizedQueryName;
        while (true)
        {
            if (servicesByOwner.TryGetValue(currentName, out List<DnsServiceBindingNamedRecord>? records) && records.Count > 0)
            {
                return new DnsServiceBindingAliasResolution(
                    DnsServiceBindingAliasResolutionStatus.Succeeded,
                    normalizedQueryName,
                    currentName,
                    aliasChain,
                    records);
            }

            if (!aliasesByOwner.TryGetValue(currentName, out DnsServiceBindingAliasRecord? aliasRecord))
            {
                return new DnsServiceBindingAliasResolution(
                    DnsServiceBindingAliasResolutionStatus.MissingTarget,
                    normalizedQueryName,
                    currentName,
                    aliasChain,
                    []);
            }

            if (!visited.Add(currentName))
            {
                return new DnsServiceBindingAliasResolution(
                    DnsServiceBindingAliasResolutionStatus.AliasLoop,
                    normalizedQueryName,
                    currentName,
                    aliasChain,
                    []);
            }

            if (aliasChain.Count >= maximumAliasDepth)
            {
                return new DnsServiceBindingAliasResolution(
                    DnsServiceBindingAliasResolutionStatus.MaxDepthExceeded,
                    normalizedQueryName,
                    currentName,
                    aliasChain,
                    []);
            }

            aliasChain.Add(currentName);
            currentName = aliasRecord.TargetName;
        }
    }

    internal static string NormalizeResolutionName(string name, string argumentName)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("The DNS resolution name must not be empty.", argumentName);
        }

        string candidate = name.Trim();
        bool absolute = candidate.EndsWith(".", StringComparison.Ordinal);
        string host = absolute ? candidate[..^1] : candidate;
        if (host.Length == 0 || host.Length > MaximumDnsNameLength)
        {
            throw new ArgumentException("The DNS resolution name is outside DNS length bounds.", argumentName);
        }

        foreach (string label in host.Split('.'))
        {
            if (!IsValidResolutionLabel(label))
            {
                throw new ArgumentException("The DNS resolution name contains an invalid label.", argumentName);
            }
        }

        return string.Join('.', host.Split('.').Select(static label => label.ToLowerInvariant())) + ".";
    }

    private static bool IsValidResolutionLabel(string label)
    {
        if (label.Length is 0 or > MaximumDnsLabelLength || label[0] == '-' || label[^1] == '-')
        {
            return false;
        }

        foreach (char c in label)
        {
            bool valid = c is >= 'a' and <= 'z'
                || c is >= 'A' and <= 'Z'
                || c is >= '0' and <= '9'
                || c == '-'
                || c == '_';
            if (!valid)
            {
                return false;
            }
        }

        return true;
    }
}
