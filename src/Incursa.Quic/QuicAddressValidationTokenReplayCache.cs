// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Incursa.Quic;

// CONTEXT: Consumed validation tokens are indexed by a SHA-256 fingerprint so replay checks do
// not retain raw token bytes, and pruning on consume keeps the cache bounded without a separate
// timer.
// SEE: code:src/Incursa.Quic/QuicAddressValidationTokenReplayCache.cs#TryConsume
// SEE: code:src/Incursa.Quic/QuicAddressValidationTokenProtector.cs#ValidateNewToken
internal sealed class QuicAddressValidationTokenReplayCache
{
    private readonly ConcurrentDictionary<string, long> consumedTokenExpirations = new();

    internal bool TryConsume(
        ReadOnlySpan<byte> token,
        DateTimeOffset expiresAt,
        DateTimeOffset now)
    {
        PruneExpired(now);

        string tokenFingerprint = Convert.ToHexString(SHA256.HashData(token));
        return consumedTokenExpirations.TryAdd(tokenFingerprint, expiresAt.ToUnixTimeSeconds());
    }

    private void PruneExpired(DateTimeOffset now)
    {
        long nowSeconds = now.ToUnixTimeSeconds();
        foreach (KeyValuePair<string, long> consumedTokenExpiration in consumedTokenExpirations)
        {
            if (consumedTokenExpiration.Value < nowSeconds)
            {
                consumedTokenExpirations.TryRemove(consumedTokenExpiration.Key, out _);
            }
        }
    }
}
