using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Incursa.Quic;

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
