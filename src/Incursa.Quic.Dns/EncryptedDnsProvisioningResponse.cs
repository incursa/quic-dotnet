// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// RFC 9464 encrypted DNS provisioning response material selected for CFG_REPLY.
/// </summary>
public sealed class EncryptedDnsProvisioningResponse
{
    internal EncryptedDnsProvisioningResponse(
        IReadOnlyList<EncryptedDnsProvisioningAttribute> attributes,
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo,
        bool requestDiscarded)
    {
        Attributes = attributes;
        DigestInfo = digestInfo;
        RequestDiscarded = requestDiscarded;
    }

    /// <summary>
    /// Gets a value indicating whether the request was discarded by policy.
    /// </summary>
    public bool RequestDiscarded { get; }

    /// <summary>
    /// Gets the ENCDNS_IP* attributes to send in CFG_REPLY.
    /// </summary>
    public IReadOnlyList<EncryptedDnsProvisioningAttribute> Attributes { get; }

    /// <summary>
    /// Gets optional ENCDNS_DIGEST_INFO to send with the CFG_REPLY.
    /// </summary>
    public EncryptedDnsProvisioningDigestInfoAttribute? DigestInfo { get; }
}
