// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicRetentionSnapshot(
    long RetainedBufferCount,
    long RetainedByteCount,
    double? OldestAgeMilliseconds)
{
    private const double MicrosecondsPerMillisecond = 1000.0;

    internal static void AddOwners(
        byte[]? firstOwner,
        byte[]? secondOwner,
        ref long retainedBufferCount,
        ref long retainedByteCount)
    {
        if (firstOwner is not null)
        {
            retainedBufferCount++;
            retainedByteCount += firstOwner.Length;
        }

        if (secondOwner is not null && !ReferenceEquals(firstOwner, secondOwner))
        {
            retainedBufferCount++;
            retainedByteCount += secondOwner.Length;
        }
    }

    internal static double? GetOldestAgeMilliseconds(ulong nowMicros, ulong? oldestSentAtMicros)
    {
        if (!oldestSentAtMicros.HasValue)
        {
            return null;
        }

        ulong ageMicros = nowMicros >= oldestSentAtMicros.Value
            ? nowMicros - oldestSentAtMicros.Value
            : 0;
        return ageMicros / MicrosecondsPerMillisecond;
    }
}

internal readonly record struct QuicReceiveRetentionSnapshot(
    long RetainedBufferCount,
    long RetainedBufferBytes,
    long BufferedBytes,
    long BufferedStreamCount);
