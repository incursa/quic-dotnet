// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Decides whether one connection may construct a contiguous application-datagram batch.
/// </summary>
/// <remarks>
/// Implementations observe only bounded distinct-stream pressure. They do not own writes, packets, or
/// transport state and cannot change the runtime-computed send budget.
/// </remarks>
internal interface IQuicApplicationDatagramBatchPolicy
{
    bool IsPromoted { get; }

    bool ShouldBuildBatch(int queuedStreamCount);
}

/// <summary>
/// Starts on the low-pressure segmented path and promotes one way after sustained queue pressure.
/// </summary>
internal sealed class QuicAdaptiveApplicationDatagramBatchPolicy : IQuicApplicationDatagramBatchPolicy
{
    internal const int DefaultRequiredConsecutivePressureTurns = 2;

    private readonly int pressureStreamCount;
    private readonly int requiredConsecutivePressureTurns;
    private int consecutivePressureTurns;
    private int promoted;

    internal QuicAdaptiveApplicationDatagramBatchPolicy(
        int pressureStreamCount = QuicConnectionRuntime.HostedApplicationDatagramBatchCapacity,
        int requiredConsecutivePressureTurns = DefaultRequiredConsecutivePressureTurns)
    {
        if (pressureStreamCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pressureStreamCount));
        }

        if (requiredConsecutivePressureTurns <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(requiredConsecutivePressureTurns));
        }

        this.pressureStreamCount = pressureStreamCount;
        this.requiredConsecutivePressureTurns = requiredConsecutivePressureTurns;
    }

    public bool IsPromoted => Volatile.Read(ref promoted) != 0;

    public bool ShouldBuildBatch(int queuedStreamCount)
    {
        if (IsPromoted)
        {
            return false;
        }

        if (queuedStreamCount < pressureStreamCount)
        {
            consecutivePressureTurns = 0;
            return true;
        }

        consecutivePressureTurns++;
        if (consecutivePressureTurns < requiredConsecutivePressureTurns)
        {
            return true;
        }

        Volatile.Write(ref promoted, 1);
        return false;
    }
}
