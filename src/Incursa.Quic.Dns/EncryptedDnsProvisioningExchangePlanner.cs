// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Deterministic RFC 9464 exchange planner for local CFG_REQUEST, CFG_REPLY, and client resolver decisions.
/// </summary>
public static class EncryptedDnsProvisioningExchangePlanner
{
    /// <summary>
    /// Creates a CFG_REQUEST payload that advertises encrypted DNS support and optional digest algorithms.
    /// </summary>
    public static EncryptedDnsProvisioningConfigurationPayload CreateSupportRequest(
        bool includeIpv4 = true,
        bool includeIpv6 = true,
        IEnumerable<ushort>? digestHashAlgorithmIdentifiers = null)
    {
        IReadOnlyList<EncryptedDnsProvisioningAttribute> attributes =
            EncryptedDnsProvisioningResponder.CreateSupportAdvertisementRequest(includeIpv4, includeIpv6);
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo = digestHashAlgorithmIdentifiers is null
            ? null
            : EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest(digestHashAlgorithmIdentifiers);

        return EncryptedDnsProvisioningConfigurationPayload.Create(
            EncryptedDnsProvisioningPayloadType.Request,
            attributes,
            digestInfo);
    }

    /// <summary>
    /// Creates a CFG_REPLY payload from a validated CFG_REQUEST payload and responder policy.
    /// </summary>
    public static EncryptedDnsProvisioningConfigurationPayload CreateReply(
        EncryptedDnsProvisioningConfigurationPayload requestPayload,
        EncryptedDnsProvisioningResponseOptions responseOptions)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentNullException.ThrowIfNull(responseOptions);
        if (requestPayload.PayloadType != EncryptedDnsProvisioningPayloadType.Request)
        {
            throw new ArgumentException("A responder reply can only be planned from a CFG_REQUEST payload.", nameof(requestPayload));
        }

        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            requestPayload.ResolverAttributes,
            responseOptions);

        return EncryptedDnsProvisioningConfigurationPayload.Create(
            EncryptedDnsProvisioningPayloadType.Reply,
            response.Attributes,
            response.DigestInfo);
    }

    /// <summary>
    /// Creates a client resolver plan from a CFG_REPLY or CFG_SET payload.
    /// </summary>
    public static EncryptedDnsProvisioningClientPlan CreateClientPlan(
        EncryptedDnsProvisioningConfigurationPayload responsePayload,
        IEnumerable<IPAddress>? cleartextResolverAddresses = null,
        IEnumerable<string>? internalDnsDomains = null,
        bool splitTunnel = false,
        bool responderUsedNullAuthentication = false,
        bool nullAuthenticationPreconfigured = false)
    {
        ArgumentNullException.ThrowIfNull(responsePayload);
        if (responsePayload.PayloadType is not EncryptedDnsProvisioningPayloadType.Reply
            and not EncryptedDnsProvisioningPayloadType.Set)
        {
            throw new ArgumentException("Client provisioning can only consume CFG_REPLY or CFG_SET payloads.", nameof(responsePayload));
        }

        return EncryptedDnsProvisioningClientPolicy.CreatePlan(
            responsePayload.ResolverAttributes,
            cleartextResolverAddresses,
            internalDnsDomains,
            splitTunnel,
            responderUsedNullAuthentication,
            nullAuthenticationPreconfigured);
    }
}
