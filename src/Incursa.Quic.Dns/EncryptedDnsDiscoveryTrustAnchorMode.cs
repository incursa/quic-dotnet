// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Trust-anchor mode used for RFC 9463 encrypted DNS resolver certificate validation.
/// </summary>
public enum EncryptedDnsDiscoveryTrustAnchorMode
{
    /// <summary>
    /// Use the default system or application PKI trust anchors.
    /// </summary>
    DefaultSystemOrApplication,

    /// <summary>
    /// Use explicitly configured trust anchors.
    /// </summary>
    Explicit,
}
