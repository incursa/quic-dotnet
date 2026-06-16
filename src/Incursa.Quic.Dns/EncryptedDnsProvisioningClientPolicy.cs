// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Pure client-side RFC 9464 policy for selecting encrypted DNS provisioning results.
/// </summary>
public static class EncryptedDnsProvisioningClientPolicy
{
    /// <summary>
    /// Creates a resolver plan from decoded CFG_REPLY or CFG_SET encrypted DNS provisioning data.
    /// </summary>
    public static EncryptedDnsProvisioningClientPlan CreatePlan(
        IEnumerable<EncryptedDnsProvisioningAttribute> encryptedDnsAttributes,
        IEnumerable<IPAddress>? cleartextResolverAddresses = null,
        IEnumerable<string>? internalDnsDomains = null,
        bool splitTunnel = false,
        bool responderUsedNullAuthentication = false,
        bool nullAuthenticationPreconfigured = false)
    {
        ArgumentNullException.ThrowIfNull(encryptedDnsAttributes);

        List<IPAddress> normalizedCleartextResolvers = NormalizeCleartextResolvers(cleartextResolverAddresses);
        List<string> normalizedInternalDomains = NormalizeInternalDnsDomains(internalDnsDomains);
        if (responderUsedNullAuthentication && !nullAuthenticationPreconfigured)
        {
            return EncryptedDnsProvisioningClientPlan.Create(
                [],
                normalizedCleartextResolvers,
                normalizedInternalDomains,
                splitTunnel,
                blockedByNullAuthentication: true);
        }

        List<EncryptedDnsProvisioningResolverEndpoint> encryptedEndpoints = [];
        foreach (EncryptedDnsProvisioningAttribute? attribute in encryptedDnsAttributes)
        {
            ArgumentNullException.ThrowIfNull(attribute);
            if (attribute.PayloadType is not EncryptedDnsProvisioningPayloadType.Reply and not EncryptedDnsProvisioningPayloadType.Set)
            {
                throw new ArgumentException("Client provisioning policy accepts only CFG_REPLY or CFG_SET ENCDNS_IP* attributes.", nameof(encryptedDnsAttributes));
            }

            foreach (IPAddress address in attribute.Addresses)
            {
                encryptedEndpoints.Add(new EncryptedDnsProvisioningResolverEndpoint(
                    address,
                    attribute.AuthenticationDomainName,
                    attribute.ServicePriority,
                    attribute.AddressFamily,
                    attribute.ServiceParameterKeys));
            }
        }

        encryptedEndpoints.Sort(static (left, right) => left.ServicePriority.CompareTo(right.ServicePriority));
        return EncryptedDnsProvisioningClientPlan.Create(
            encryptedEndpoints,
            normalizedCleartextResolvers,
            normalizedInternalDomains,
            splitTunnel,
            blockedByNullAuthentication: false);
    }

    /// <summary>
    /// Validates an encrypted DNS resolver certificate using the conveyed ADN and optional ENCDNS_DIGEST_INFO.
    /// </summary>
    public static EncryptedDnsProvisioningCertificateValidationStatus ValidateResolverCertificate(
        EncryptedDnsProvisioningResolverEndpoint resolverEndpoint,
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo,
        ReadOnlySpan<byte> subjectPublicKeyInfoDer,
        bool authenticationDomainNameMatchesCertificate)
    {
        ArgumentNullException.ThrowIfNull(resolverEndpoint);

        if (digestInfo is not null && DigestAppliesToEndpoint(digestInfo, resolverEndpoint))
        {
            if (subjectPublicKeyInfoDer.IsEmpty)
            {
                return EncryptedDnsProvisioningCertificateValidationStatus.NonRecoverableFailure;
            }

            if (digestInfo.HashAlgorithmIdentifiers.Count == 1
                && digestInfo.HashAlgorithmIdentifiers[0] == EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier)
            {
                byte[] computedDigest = EncryptedDnsProvisioningDigestInfoAttribute
                    .ComputeSha2_256SubjectPublicKeyInfoDigest(subjectPublicKeyInfoDer);
                return computedDigest.AsSpan().SequenceEqual(digestInfo.CertificateDigest.Span)
                    ? EncryptedDnsProvisioningCertificateValidationStatus.ValidatedBySubjectPublicKeyInfoDigest
                    : EncryptedDnsProvisioningCertificateValidationStatus.NonRecoverableFailure;
            }

            return EncryptedDnsProvisioningCertificateValidationStatus.NonRecoverableFailure;
        }

        return authenticationDomainNameMatchesCertificate
            ? EncryptedDnsProvisioningCertificateValidationStatus.ValidatedByAuthenticationDomainName
            : EncryptedDnsProvisioningCertificateValidationStatus.NonRecoverableFailure;
    }

    private static bool DigestAppliesToEndpoint(
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo,
        EncryptedDnsProvisioningResolverEndpoint resolverEndpoint)
    {
        return digestInfo.AppliesToProvisioningAttributeAuthenticationDomainName
            || string.Equals(
                digestInfo.AuthenticationDomainName,
                resolverEndpoint.AuthenticationDomainName,
                StringComparison.OrdinalIgnoreCase);
    }

    private static List<IPAddress> NormalizeCleartextResolvers(IEnumerable<IPAddress>? cleartextResolverAddresses)
    {
        List<IPAddress> normalized = [];
        if (cleartextResolverAddresses is null)
        {
            return normalized;
        }

        foreach (IPAddress? address in cleartextResolverAddresses)
        {
            ArgumentNullException.ThrowIfNull(address);
            normalized.Add(address);
        }

        return normalized;
    }

    private static List<string> NormalizeInternalDnsDomains(IEnumerable<string>? internalDnsDomains)
    {
        List<string> normalized = [];
        if (internalDnsDomains is null)
        {
            return normalized;
        }

        foreach (string? domain in internalDnsDomains)
        {
            normalized.Add(EncryptedDnsProvisioningAttribute.NormalizeAuthenticationDomainName(domain));
        }

        return normalized;
    }
}
