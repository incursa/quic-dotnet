// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Operator-facing RFC 9461 DNS service binding publication guidance.
/// </summary>
public sealed class DnsServiceBindingOperatorGuidance
{
    private DnsServiceBindingOperatorGuidance(bool resolutionSpeedHighPriority, bool equivalentHttpsRecordPublished)
    {
        ResolutionSpeedHighPriority = resolutionSpeedHighPriority;
        EquivalentHttpsRecordPublished = equivalentHttpsRecordPublished;
    }

    /// <summary>
    /// Gets a value indicating whether resolution speed is a high publication priority.
    /// </summary>
    public bool ResolutionSpeedHighPriority { get; }

    /// <summary>
    /// Gets a value indicating whether an equivalent HTTPS RR is published.
    /// </summary>
    public bool EquivalentHttpsRecordPublished { get; }

    /// <summary>
    /// Gets a value indicating whether the operator should publish an equivalent HTTPS RR.
    /// </summary>
    public bool ShouldPublishEquivalentHttpsRecord => !EquivalentHttpsRecordPublished;

    /// <summary>
    /// Gets a value indicating whether AliasMode records should be avoided.
    /// </summary>
    public bool ShouldAvoidAliasMode => ResolutionSpeedHighPriority;

    /// <summary>
    /// Gets a value indicating whether TargetName should follow the SVCB Section 10.2 convention.
    /// </summary>
    public bool ShouldUseFastResolutionTargetNameConvention => ResolutionSpeedHighPriority;

    /// <summary>
    /// Creates operator guidance for DNS service binding publication.
    /// </summary>
    public static DnsServiceBindingOperatorGuidance Create(
        bool resolutionSpeedHighPriority,
        bool equivalentHttpsRecordPublished = false)
    {
        return new DnsServiceBindingOperatorGuidance(resolutionSpeedHighPriority, equivalentHttpsRecordPublished);
    }
}
