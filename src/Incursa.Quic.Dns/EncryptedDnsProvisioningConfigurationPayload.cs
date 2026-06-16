// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Deterministic local model for RFC 9464 encrypted DNS attributes inside an IKEv2 Configuration Payload.
/// </summary>
public sealed class EncryptedDnsProvisioningConfigurationPayload
{
    private EncryptedDnsProvisioningConfigurationPayload(
        EncryptedDnsProvisioningPayloadType payloadType,
        IReadOnlyList<EncryptedDnsProvisioningAttribute> resolverAttributes,
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo)
    {
        PayloadType = payloadType;
        ResolverAttributes = resolverAttributes;
        DigestInfo = digestInfo;
    }

    /// <summary>
    /// Gets the modeled IKEv2 Configuration Payload type.
    /// </summary>
    public EncryptedDnsProvisioningPayloadType PayloadType { get; }

    /// <summary>
    /// Gets ENCDNS_IP* attributes in this payload.
    /// </summary>
    public IReadOnlyList<EncryptedDnsProvisioningAttribute> ResolverAttributes { get; }

    /// <summary>
    /// Gets the optional ENCDNS_DIGEST_INFO attribute in this payload.
    /// </summary>
    public EncryptedDnsProvisioningDigestInfoAttribute? DigestInfo { get; }

    /// <summary>
    /// Gets a value indicating whether the payload carries no encrypted DNS attributes.
    /// </summary>
    public bool IsEmpty => ResolverAttributes.Count == 0 && DigestInfo is null;

    /// <summary>
    /// Creates a validated local Configuration Payload model from already-decoded RFC 9464 attributes.
    /// </summary>
    public static EncryptedDnsProvisioningConfigurationPayload Create(
        EncryptedDnsProvisioningPayloadType payloadType,
        IEnumerable<EncryptedDnsProvisioningAttribute> resolverAttributes,
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo = null)
    {
        ArgumentNullException.ThrowIfNull(resolverAttributes);

        List<EncryptedDnsProvisioningAttribute> normalizedAttributes = [];
        foreach (EncryptedDnsProvisioningAttribute? attribute in resolverAttributes)
        {
            ArgumentNullException.ThrowIfNull(attribute);
            if (attribute.PayloadType != payloadType)
            {
                throw new ArgumentException("Configuration payload attributes must match the payload type.", nameof(resolverAttributes));
            }

            normalizedAttributes.Add(attribute);
        }

        if (digestInfo is not null && digestInfo.PayloadType != payloadType)
        {
            throw new ArgumentException("Configuration payload digest information must match the payload type.", nameof(digestInfo));
        }

        return new EncryptedDnsProvisioningConfigurationPayload(
            payloadType,
            new ReadOnlyCollection<EncryptedDnsProvisioningAttribute>(normalizedAttributes),
            digestInfo);
    }
}
