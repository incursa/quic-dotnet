// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Pure RFC 9464 response policy for encrypted DNS provisioning attributes.
/// </summary>
public static class EncryptedDnsProvisioningResponder
{
    /// <summary>
    /// Creates zero-length CFG_REQUEST ENCDNS_IP* attributes that advertise encrypted DNS support.
    /// </summary>
    public static IReadOnlyList<EncryptedDnsProvisioningAttribute> CreateSupportAdvertisementRequest(
        bool includeIpv4 = true,
        bool includeIpv6 = true)
    {
        if (!includeIpv4 && !includeIpv6)
        {
            throw new ArgumentException("A CFG_REQUEST support advertisement must include ENCDNS_IP4, ENCDNS_IP6, or both.", nameof(includeIpv4));
        }

        List<EncryptedDnsProvisioningAttribute> attributes = [];
        if (includeIpv4)
        {
            attributes.Add(EncryptedDnsProvisioningAttribute.CreateEmpty(
                EncryptedDnsProvisioningPayloadType.Request,
                EncryptedDnsProvisioningAddressFamily.Ip4));
        }

        if (includeIpv6)
        {
            attributes.Add(EncryptedDnsProvisioningAttribute.CreateEmpty(
                EncryptedDnsProvisioningPayloadType.Request,
                EncryptedDnsProvisioningAddressFamily.Ip6));
        }

        return new ReadOnlyCollection<EncryptedDnsProvisioningAttribute>(attributes);
    }

    /// <summary>
    /// Selects CFG_REPLY attributes for an RFC 9464 CFG_REQUEST.
    /// </summary>
    public static EncryptedDnsProvisioningResponse CreateReply(
        IEnumerable<EncryptedDnsProvisioningAttribute> requestAttributes,
        EncryptedDnsProvisioningResponseOptions options)
    {
        if (requestAttributes is null)
        {
            throw new ArgumentNullException(nameof(requestAttributes));
        }

        ArgumentNullException.ThrowIfNull(options);

        List<EncryptedDnsProvisioningAttribute> uniqueRequests = [];
        HashSet<string> fingerprints = new(StringComparer.Ordinal);
        int duplicateCount = 0;
        foreach (EncryptedDnsProvisioningAttribute? request in requestAttributes)
        {
            ArgumentNullException.ThrowIfNull(request);
            if (request.PayloadType != EncryptedDnsProvisioningPayloadType.Request)
            {
                throw new ArgumentException("Provisioning requests must be CFG_REQUEST ENCDNS_IP* attributes.", nameof(requestAttributes));
            }

            string fingerprint = Convert.ToHexString(request.Encode());
            if (!fingerprints.Add(fingerprint))
            {
                duplicateCount++;
                if (duplicateCount > options.DuplicateAttributeDiscardThreshold)
                {
                    return new EncryptedDnsProvisioningResponse(
                        new ReadOnlyCollection<EncryptedDnsProvisioningAttribute>([]),
                        digestInfo: null,
                        requestDiscarded: true);
                }

                continue;
            }

            uniqueRequests.Add(request);
        }

        List<EncryptedDnsProvisioningAttribute> replies = [];
        foreach (EncryptedDnsProvisioningAttribute request in uniqueRequests)
        {
            foreach (EncryptedDnsProvisioningAttribute configuration in options.AvailableConfigurations)
            {
                if (configuration.AddressFamily == request.AddressFamily)
                {
                    replies.Add(configuration);
                }
            }
        }

        replies.Sort(static (left, right) => left.ServicePriority.CompareTo(right.ServicePriority));
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo = replies.Count != 0 && options.IncludeDigestInfo
            ? options.DigestInfo
            : null;
        return new EncryptedDnsProvisioningResponse(
            new ReadOnlyCollection<EncryptedDnsProvisioningAttribute>(replies),
            digestInfo,
            requestDiscarded: false);
    }
}
