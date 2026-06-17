// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents the deterministic result reported by an encrypted DNS integration adapter.
/// </summary>
public sealed class EncryptedDnsAdapterResult
{
    private EncryptedDnsAdapterResult(
        EncryptedDnsAdapterResultStatus status,
        string detail,
        int appliedItemCount)
    {
        Status = status;
        Detail = detail;
        AppliedItemCount = appliedItemCount;
    }

    /// <summary>
    /// Gets the adapter result status.
    /// </summary>
    public EncryptedDnsAdapterResultStatus Status { get; }

    /// <summary>
    /// Gets the operator-facing status detail.
    /// </summary>
    public string Detail { get; }

    /// <summary>
    /// Gets the number of records, attempts, or payload groups applied by the adapter.
    /// </summary>
    public int AppliedItemCount { get; }

    /// <summary>
    /// Gets a value indicating whether the adapter applied the requested operation.
    /// </summary>
    public bool Applied => Status == EncryptedDnsAdapterResultStatus.Applied;

    /// <summary>
    /// Creates an applied result.
    /// </summary>
    public static EncryptedDnsAdapterResult CreateApplied(string detail, int appliedItemCount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);
        if (appliedItemCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(appliedItemCount), appliedItemCount, "The applied item count cannot be negative.");
        }

        return new EncryptedDnsAdapterResult(EncryptedDnsAdapterResultStatus.Applied, detail, appliedItemCount);
    }

    /// <summary>
    /// Creates a blocked result.
    /// </summary>
    public static EncryptedDnsAdapterResult CreateBlocked(string detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);
        return new EncryptedDnsAdapterResult(EncryptedDnsAdapterResultStatus.Blocked, detail, appliedItemCount: 0);
    }

    /// <summary>
    /// Creates a failed result.
    /// </summary>
    public static EncryptedDnsAdapterResult CreateFailed(string detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);
        return new EncryptedDnsAdapterResult(EncryptedDnsAdapterResultStatus.Failed, detail, appliedItemCount: 0);
    }
}
