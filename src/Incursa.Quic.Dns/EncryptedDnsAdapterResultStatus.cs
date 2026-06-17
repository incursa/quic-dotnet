// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Adapter execution status for deterministic encrypted DNS integration proof.
/// </summary>
public enum EncryptedDnsAdapterResultStatus
{
    /// <summary>
    /// The adapter accepted and applied the requested operation.
    /// </summary>
    Applied = 0,

    /// <summary>
    /// Local policy or plan state blocked the operation before a live adapter call.
    /// </summary>
    Blocked = 1,

    /// <summary>
    /// The adapter attempted the operation and reported failure.
    /// </summary>
    Failed = 2,
}
