// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Identifies the result of DNS service binding AliasMode chain resolution.
/// </summary>
public enum DnsServiceBindingAliasResolutionStatus
{
    /// <summary>
    /// Resolution found one or more ServiceMode records.
    /// </summary>
    Succeeded,

    /// <summary>
    /// Resolution stopped at a name that had neither ServiceMode records nor an AliasMode target.
    /// </summary>
    MissingTarget,

    /// <summary>
    /// Resolution encountered an AliasMode loop.
    /// </summary>
    AliasLoop,

    /// <summary>
    /// Resolution exceeded the caller-supplied alias depth limit.
    /// </summary>
    MaxDepthExceeded,
}
