// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0049")]
public sealed class REQ_QUIC_CRT_0049
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TimerPriorityUsesTheSequenceTieBreakerForEqualDeadlines()
    {
        QuicConnectionTimerPriority earlierSequence = new(1_000, 3);
        QuicConnectionTimerPriority laterSequence = new(1_000, 4);
        QuicConnectionTimerPriority earlierDueTick = new(999, 99);

        Assert.True(earlierSequence < laterSequence);
        Assert.True(earlierSequence <= laterSequence);
        Assert.True(laterSequence > earlierSequence);
        Assert.True(laterSequence >= earlierSequence);
        Assert.True(earlierDueTick < earlierSequence);
        Assert.True(earlierDueTick <= earlierSequence);
        Assert.Equal(0, earlierSequence.CompareTo(new QuicConnectionTimerPriority(1_000, 3)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DeadlineSchedulerUsesArmSequenceToOrderEqualDueTimersDeterministically()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(9);

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 100))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.CloseLifetime, 100))
        {
            scheduler.Apply(handle, runtime, effect);
        }

        Assert.True(scheduler.TryDequeueDueEntry(100, out QuicConnectionRuntimeScheduledTimerEntry firstEntry));
        Assert.True(scheduler.TryDequeueDueEntry(100, out QuicConnectionRuntimeScheduledTimerEntry secondEntry));

        Assert.Equal(QuicConnectionTimerKind.IdleTimeout, firstEntry.TimerKind);
        Assert.Equal(QuicConnectionTimerKind.CloseLifetime, secondEntry.TimerKind);
        Assert.True(firstEntry.Priority < secondEntry.Priority);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DeadlineSchedulerCompactsStaleEntriesDuringRepeatedRearms()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeDeadlineScheduler scheduler = new();
        QuicConnectionHandle handle = new(49);

        for (int index = 0; index < 384; index++)
        {
            foreach (QuicConnectionEffect effect in runtime.SetTimerDeadline(QuicConnectionTimerKind.Recovery, 1_000 + index))
            {
                scheduler.Apply(handle, runtime, effect);
            }
        }

        Assert.Equal(1, scheduler.RegistrationCount);
        Assert.InRange(scheduler.ScheduledEntryCount, 1, 128);

        Assert.False(scheduler.TryDequeueDueEntry(1_382, out _));
        Assert.True(scheduler.TryDequeueDueEntry(1_383, out QuicConnectionRuntimeScheduledTimerEntry entry));
        Assert.Equal(QuicConnectionTimerKind.Recovery, entry.TimerKind);
        Assert.Equal(1_383L, entry.DueTicks);
    }
}
