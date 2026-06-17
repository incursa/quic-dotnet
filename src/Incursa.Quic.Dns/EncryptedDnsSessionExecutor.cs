// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Establishes planned encrypted DNS sessions through an explicit connector adapter.
/// </summary>
public static class EncryptedDnsSessionExecutor
{
    /// <summary>
    /// Attempts session establishment in the deterministic order supplied by the planner.
    /// </summary>
    public static EncryptedDnsAdapterResult ConnectFirst(
        IEnumerable<EncryptedDnsSessionAttempt> attempts,
        IEncryptedDnsSessionConnector connector)
    {
        ArgumentNullException.ThrowIfNull(attempts);
        ArgumentNullException.ThrowIfNull(connector);

        bool attempted = false;
        foreach (EncryptedDnsSessionAttempt? attempt in attempts)
        {
            ArgumentNullException.ThrowIfNull(attempt);
            attempted = true;
            EncryptedDnsAdapterResult result = connector.Connect(attempt);
            if (result.Status == EncryptedDnsAdapterResultStatus.Applied)
            {
                return result;
            }
        }

        return attempted
            ? EncryptedDnsAdapterResult.CreateFailed("All planned encrypted DNS session attempts failed.")
            : EncryptedDnsAdapterResult.CreateBlocked("The encrypted DNS session plan contains no attempts.");
    }
}
