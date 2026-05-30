// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;

namespace Incursa.Quic.Dns;

/// <summary>
/// DoQ client usage profile.
/// </summary>
public enum DoqClientProfile
{
    /// <summary>
    /// No fallback on DoQ failure. Fail hard and surface the error immediately.
    /// </summary>
    Strict = 0,

    /// <summary>
    /// On DoQ connection failure, back off from DoQ for the configured period
    /// and fall back to an alternative transport.
    /// </summary>
    Opportunistic = 1,
}

/// <summary>
/// In-memory cache mapping a server endpoint to the last DoQ failure timestamp.
/// Used by <see cref="DoqClient"/> in Opportunistic profile to avoid repeated
/// DoQ attempts to a failing server.
/// </summary>
public sealed class DoqFallbackCache
{
    private readonly ConcurrentDictionary<string, DateTime> failures = new(StringComparer.OrdinalIgnoreCase);
    private TimeSpan backoffPeriod;

    /// <summary>
    /// Initializes a new instance of the <see cref="DoqFallbackCache"/> class
    /// with the specified backoff period.
    /// </summary>
    public DoqFallbackCache(TimeSpan backoffPeriod)
    {
        if (backoffPeriod <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(backoffPeriod), backoffPeriod, "Backoff period must be positive.");
        }

        this.backoffPeriod = backoffPeriod;
    }

    /// <summary>
    /// Gets or sets the backoff period applied after a DoQ failure.
    /// </summary>
    public TimeSpan BackoffPeriod
    {
        get => backoffPeriod;
        set
        {
            if (value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, "Backoff period must be positive.");
            }

            backoffPeriod = value;
        }
    }

    /// <summary>
    /// Records a DoQ failure for the given server endpoint at the current UTC time.
    /// </summary>
    public void RecordFailure(string endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        failures[endpoint] = DateTime.UtcNow;
    }

    /// <summary>
    /// Gets the remaining backoff time for the given endpoint.
    /// Returns <see cref="TimeSpan.Zero"/> if no backoff is active.
    /// </summary>
    public TimeSpan GetRemainingBackoff(string endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        if (!failures.TryGetValue(endpoint, out DateTime lastFailure))
        {
            return TimeSpan.Zero;
        }

        TimeSpan elapsed = DateTime.UtcNow - lastFailure;
        TimeSpan remaining = backoffPeriod - elapsed;
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    /// <summary>
    /// Returns a value indicating whether DoQ is currently backed off for the given endpoint.
    /// </summary>
    public bool IsBackedOff(string endpoint)
        => GetRemainingBackoff(endpoint) > TimeSpan.Zero;

    /// <summary>
    /// Removes the failure record for the given endpoint, allowing an immediate retry.
    /// </summary>
    public void ClearFailure(string endpoint)
    {
        failures.TryRemove(endpoint, out _);
    }

    /// <summary>
    /// Clears all failure records.
    /// </summary>
    public void ClearAll()
    {
        failures.Clear();
    }
}
