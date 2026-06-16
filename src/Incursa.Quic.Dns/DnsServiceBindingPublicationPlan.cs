// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Text;

namespace Incursa.Quic.Dns;

/// <summary>
/// Builds deterministic operator publication records for RFC 9461 DNS service bindings.
/// </summary>
public sealed class DnsServiceBindingPublicationPlan
{
    private const int DefaultTtlSeconds = 300;
    private const ushort SvcbResourceRecordType = 64;
    private const ushort HttpsResourceRecordType = 65;

    private DnsServiceBindingPublicationPlan(
        IReadOnlyList<DnsServiceBindingPublicationRecord> records,
        bool avoidsAliasMode,
        bool includesEquivalentHttpsRecord)
    {
        Records = new ReadOnlyCollection<DnsServiceBindingPublicationRecord>([.. records]);
        AvoidsAliasMode = avoidsAliasMode;
        IncludesEquivalentHttpsRecord = includesEquivalentHttpsRecord;
    }

    /// <summary>
    /// Gets the deterministic publication records.
    /// </summary>
    public IReadOnlyList<DnsServiceBindingPublicationRecord> Records { get; }

    /// <summary>
    /// Gets a value indicating whether the plan avoids AliasMode for fast resolution.
    /// </summary>
    public bool AvoidsAliasMode { get; }

    /// <summary>
    /// Gets a value indicating whether the plan includes an equivalent HTTPS record.
    /// </summary>
    public bool IncludesEquivalentHttpsRecord { get; }

    /// <summary>
    /// Creates a DNS service binding publication plan.
    /// </summary>
    public static DnsServiceBindingPublicationPlan Create(
        DnsServiceTransport transport,
        DnsServiceBindingRecord record,
        string targetName,
        DnsServiceBindingOperatorGuidance? guidance = null,
        int ttlSeconds = DefaultTtlSeconds)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (ttlSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ttlSeconds), ttlSeconds, "DNS publication TTL must be positive.");
        }

        string normalizedTargetName = DnsServiceBindingAliasResolver.NormalizeResolutionName(targetName, nameof(targetName));
        string ownerName = DnsServiceBindingAliasResolver.NormalizeResolutionName(
            DnsServiceBindingDefaults.CreateServiceName(record.AuthenticationName, transport, record.Port),
            nameof(record));
        DnsServiceBindingOperatorGuidance effectiveGuidance = guidance ?? DnsServiceBindingOperatorGuidance.Create(false, equivalentHttpsRecordPublished: true);

        List<string> parameters = BuildPresentationParameters(record);
        List<DnsServiceBindingPublicationRecord> records =
        [
            new DnsServiceBindingPublicationRecord(
                ownerName,
                SvcbResourceRecordType,
                "SVCB",
                ttlSeconds,
                priority: 1,
                normalizedTargetName,
                parameters),
        ];

        bool includeEquivalentHttps = effectiveGuidance.ShouldPublishEquivalentHttpsRecord
            && record.AlpnProtocols.Any(DnsServiceBindingRecord.IsHttpAlpn);
        if (includeEquivalentHttps)
        {
            records.Add(new DnsServiceBindingPublicationRecord(
                DnsServiceBindingAliasResolver.NormalizeResolutionName(record.AuthenticationName, nameof(record)),
                HttpsResourceRecordType,
                "HTTPS",
                ttlSeconds,
                priority: 1,
                normalizedTargetName,
                parameters));
        }

        return new DnsServiceBindingPublicationPlan(
            records,
            effectiveGuidance.ShouldAvoidAliasMode,
            includeEquivalentHttps);
    }

    private static List<string> BuildPresentationParameters(DnsServiceBindingRecord record)
    {
        List<string> parameters = [];
        if (record.AlpnProtocols.Count != 0)
        {
            parameters.Add("alpn=\"" + EscapeQuotedValue(string.Join(',', record.AlpnProtocols)) + "\"");
        }

        if (record.Port.HasValue)
        {
            parameters.Add("port=" + record.Port.Value.ToString(CultureInfo.InvariantCulture));
        }

        if (record.DohPathTemplate is not null)
        {
            parameters.Add("dohpath=\"" + EscapeQuotedValue(record.DohPathTemplate) + "\"");
        }

        foreach (KeyValuePair<string, string> parameter in record.HttpsServiceParameters.OrderBy(static item => item.Key, StringComparer.OrdinalIgnoreCase))
        {
            parameters.Add(parameter.Key + "=\"" + EscapeQuotedValue(parameter.Value) + "\"");
        }

        return parameters;
    }

    private static string EscapeQuotedValue(string value)
    {
        StringBuilder builder = new(value.Length);
        foreach (char c in value)
        {
            if (c is '"' or '\\')
            {
                builder.Append('\\');
            }

            builder.Append(c);
        }

        return builder.ToString();
    }
}

/// <summary>
/// Represents one DNS presentation-format publication record.
/// </summary>
public sealed class DnsServiceBindingPublicationRecord
{
    internal DnsServiceBindingPublicationRecord(
        string ownerName,
        ushort resourceRecordType,
        string resourceRecordTypeName,
        int ttlSeconds,
        ushort priority,
        string targetName,
        IReadOnlyList<string> parameters)
    {
        OwnerName = ownerName;
        ResourceRecordType = resourceRecordType;
        ResourceRecordTypeName = resourceRecordTypeName;
        TtlSeconds = ttlSeconds;
        Priority = priority;
        TargetName = targetName;
        Parameters = new ReadOnlyCollection<string>([.. parameters]);
    }

    /// <summary>
    /// Gets the owner name.
    /// </summary>
    public string OwnerName { get; }

    /// <summary>
    /// Gets the numeric resource record type.
    /// </summary>
    public ushort ResourceRecordType { get; }

    /// <summary>
    /// Gets the presentation-format resource record type name.
    /// </summary>
    public string ResourceRecordTypeName { get; }

    /// <summary>
    /// Gets the TTL in seconds.
    /// </summary>
    public int TtlSeconds { get; }

    /// <summary>
    /// Gets the ServiceMode priority value.
    /// </summary>
    public ushort Priority { get; }

    /// <summary>
    /// Gets the ServiceMode TargetName.
    /// </summary>
    public string TargetName { get; }

    /// <summary>
    /// Gets deterministic presentation-format SvcParams.
    /// </summary>
    public IReadOnlyList<string> Parameters { get; }

    /// <summary>
    /// Formats the record as one DNS master-file presentation line.
    /// </summary>
    public string ToPresentationString()
    {
        string prefix = string.Create(
            CultureInfo.InvariantCulture,
            $"{OwnerName} {TtlSeconds} IN {ResourceRecordTypeName} {Priority} {TargetName}");
        return Parameters.Count == 0
            ? prefix
            : prefix + " " + string.Join(' ', Parameters);
    }
}
