// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Local status for router or forwarder encrypted DNS advertisement planning.
/// </summary>
public enum EncryptedDnsDiscoveryAdvertisementStatus
{
    /// <summary>
    /// At least one adapter-neutral advertisement payload was produced.
    /// </summary>
    Ready,

    /// <summary>
    /// The requested populated advertisements had no usable resolver addresses for the selected surfaces.
    /// </summary>
    NoUsableAddresses,

    /// <summary>
    /// Local policy disabled all advertisement surfaces.
    /// </summary>
    BlockedByPolicy,
}
