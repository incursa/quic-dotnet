// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Responder policy for RFC 9464 encrypted DNS provisioning replies.
/// </summary>
public sealed class EncryptedDnsProvisioningResponseOptions
{
    private EncryptedDnsProvisioningResponseOptions(
        IReadOnlyList<EncryptedDnsProvisioningAttribute> availableConfigurations,
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo,
        int duplicateAttributeDiscardThreshold,
        bool includeDigestInfo,
        bool requireAlpnServiceParameter)
    {
        AvailableConfigurations = availableConfigurations;
        DigestInfo = digestInfo;
        DuplicateAttributeDiscardThreshold = duplicateAttributeDiscardThreshold;
        IncludeDigestInfo = includeDigestInfo;
        RequireAlpnServiceParameter = requireAlpnServiceParameter;
    }

    /// <summary>
    /// Gets the encrypted DNS configurations available to return in CFG_REPLY payloads.
    /// </summary>
    public IReadOnlyList<EncryptedDnsProvisioningAttribute> AvailableConfigurations { get; }

    /// <summary>
    /// Gets the optional digest information to return with accepted configurations.
    /// </summary>
    public EncryptedDnsProvisioningDigestInfoAttribute? DigestInfo { get; }

    /// <summary>
    /// Gets the repeated-attribute threshold after which the responder discards the request.
    /// </summary>
    public int DuplicateAttributeDiscardThreshold { get; }

    /// <summary>
    /// Gets a value indicating whether digest information should be included when available.
    /// </summary>
    public bool IncludeDigestInfo { get; }

    /// <summary>
    /// Gets a value indicating whether reply configurations must carry an ALPN service parameter.
    /// </summary>
    public bool RequireAlpnServiceParameter { get; }

    /// <summary>
    /// Creates response policy options.
    /// </summary>
    public static EncryptedDnsProvisioningResponseOptions Create(
        IEnumerable<EncryptedDnsProvisioningAttribute> availableConfigurations,
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo = null,
        int duplicateAttributeDiscardThreshold = 16,
        bool includeDigestInfo = true,
        bool requireAlpnServiceParameter = true)
    {
        if (availableConfigurations is null)
        {
            throw new ArgumentNullException(nameof(availableConfigurations));
        }

        if (duplicateAttributeDiscardThreshold < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(duplicateAttributeDiscardThreshold), duplicateAttributeDiscardThreshold, "The duplicate discard threshold must be positive.");
        }

        List<EncryptedDnsProvisioningAttribute> normalized = [];
        foreach (EncryptedDnsProvisioningAttribute? configuration in availableConfigurations)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            if (configuration.PayloadType != EncryptedDnsProvisioningPayloadType.Reply)
            {
                throw new ArgumentException("Available encrypted DNS configurations must be CFG_REPLY ENCDNS_IP* attributes.", nameof(availableConfigurations));
            }

            if (configuration.AddressCount == 0)
            {
                throw new ArgumentException("Available encrypted DNS configurations must contain at least one IP address.", nameof(availableConfigurations));
            }

            if (requireAlpnServiceParameter && !configuration.ServiceParameterKeys.Contains("alpn", StringComparer.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Available encrypted DNS configurations must include an ALPN service parameter unless ALPN preference is explicitly disabled.", nameof(availableConfigurations));
            }

            normalized.Add(configuration);
        }

        EncryptedDnsProvisioningDigestInfoAttribute? normalizedDigest = digestInfo;
        if (normalizedDigest is not null && normalizedDigest.PayloadType != EncryptedDnsProvisioningPayloadType.Reply)
        {
            throw new ArgumentException("Digest information for a response must be a CFG_REPLY ENCDNS_DIGEST_INFO attribute.", nameof(digestInfo));
        }

        normalized.Sort(static (left, right) => left.ServicePriority.CompareTo(right.ServicePriority));
        return new EncryptedDnsProvisioningResponseOptions(
            normalized,
            normalizedDigest,
            duplicateAttributeDiscardThreshold,
            includeDigestInfo,
            requireAlpnServiceParameter);
    }
}
