// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Threading.Channels;

namespace Incursa.Quic;

/// <summary>
/// Tracks timer registrations for a single runtime shard and exposes due work back to that shard's inbox.
/// </summary>
/// <remarks>
/// The shard owns this scheduler and drives it from a single consumer loop, so the scheduler itself does not
/// take locks.
/// </remarks>
internal sealed class QuicConnectionRuntimeDeadlineScheduler
{
    private const int InitialTimerHeapCapacity = 256;
    private const int StaleTimerHeapCompactionThreshold = 256;
    private const int StaleTimerHeapCompactionFactor = 4;

    private PriorityQueue<QuicConnectionRuntimeScheduledTimerEntry, QuicConnectionTimerPriority> timerHeap = new();
    private readonly Dictionary<QuicConnectionRuntimeScheduledTimerKey, QuicConnectionRuntimeScheduledTimerRegistration> registrations = [];

    /// <summary>
    /// Gets the number of currently active timer registrations.
    /// </summary>
    public int RegistrationCount => registrations.Count;

    /// <summary>
    /// Gets the number of scheduled heap entries, including stale entries waiting to be skipped or compacted.
    /// </summary>
    internal int ScheduledEntryCount => timerHeap.Count;

    /// <summary>
    /// Applies a runtime-emitted timer effect to the scheduler.
    /// </summary>
    public void Apply(QuicConnectionHandle handle, QuicConnectionRuntime runtime, QuicConnectionEffect effect)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(effect);

        switch (effect)
        {
            case QuicConnectionArmTimerEffect armEffect:
                Arm(handle, runtime, armEffect);
                break;
            case QuicConnectionCancelTimerEffect cancelEffect:
                Cancel(handle, cancelEffect);
                break;
        }
    }

    /// <summary>
    /// Arms or replaces a timer registration for the supplied connection handle.
    /// </summary>
    /// <remarks>
    /// Newer generations win; stale generations are ignored so previously enqueued heap entries can be skipped later.
    /// </remarks>
    public void Arm(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        QuicConnectionArmTimerEffect effect)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        QuicConnectionRuntimeScheduledTimerKey key = new(handle, effect.TimerKind);
        if (registrations.TryGetValue(key, out QuicConnectionRuntimeScheduledTimerRegistration existingRegistration)
            && existingRegistration.Generation > effect.Generation)
        {
            return;
        }

        QuicConnectionRuntimeScheduledTimerRegistration registration = new(
            runtime,
            effect.Priority.DueTicks,
            effect.Generation,
            effect.Priority);

        registrations[key] = registration;

        QuicConnectionRuntimeScheduledTimerEntry entry = new(
            handle,
            runtime,
            effect.TimerKind,
            effect.Priority.DueTicks,
            effect.Generation,
            effect.Priority);

        if (!CompactStaleEntriesIfNeeded())
        {
            timerHeap.Enqueue(entry, effect.Priority);
        }
    }

    /// <summary>
    /// Cancels a timer registration when the cancellation generation is current.
    /// </summary>
    public void Cancel(QuicConnectionHandle handle, QuicConnectionCancelTimerEffect effect)
    {
        QuicConnectionRuntimeScheduledTimerKey key = new(handle, effect.TimerKind);
        if (!registrations.TryGetValue(key, out QuicConnectionRuntimeScheduledTimerRegistration registration))
        {
            return;
        }

        if (registration.Generation > effect.Generation)
        {
            return;
        }

        registrations.Remove(key);
        _ = CompactStaleEntriesIfNeeded();
    }

    /// <summary>
    /// Computes the wait time until the next valid scheduled timer.
    /// </summary>
    public bool TryGetNextWait(long nowTicks, out TimeSpan wait)
    {
        if (!TryPeekNextValidEntry(out QuicConnectionRuntimeScheduledTimerEntry entry))
        {
            wait = default;
            return false;
        }

        long remainingTicks = entry.DueTicks - nowTicks;
        wait = remainingTicks <= 0
            ? TimeSpan.Zero
            : StopwatchTicksToTimeSpan(remainingTicks);
        return true;
    }

    /// <summary>
    /// Removes and returns the next due timer entry if its registration is still current.
    /// </summary>
    public bool TryDequeueDueEntry(long nowTicks, out QuicConnectionRuntimeScheduledTimerEntry entry)
    {
        while (TryPeekNextValidEntry(out entry))
        {
            if (entry.DueTicks > nowTicks)
            {
                entry = default;
                return false;
            }

            timerHeap.Dequeue();
            QuicConnectionRuntimeScheduledTimerKey key = new(entry.Handle, entry.TimerKind);
            if (registrations.TryGetValue(key, out QuicConnectionRuntimeScheduledTimerRegistration registration)
                && ReferenceEquals(registration.Runtime, entry.Runtime)
                && registration.Generation == entry.Generation
                && registration.DueTicks == entry.DueTicks)
            {
                registrations.Remove(key);
                return true;
            }
        }

        entry = default;
        return false;
    }

    /// <summary>
    /// Enqueues due timer expirations into the shard inbox until the inbox applies backpressure.
    /// </summary>
    public int EnqueueDueEntries(long nowTicks, ChannelWriter<QuicConnectionRuntimeShardWorkItem> inbox)
    {
        ArgumentNullException.ThrowIfNull(inbox);

        int count = 0;
        while (TryDequeueDueEntry(nowTicks, out QuicConnectionRuntimeScheduledTimerEntry entry))
        {
            if (!inbox.TryWrite(new QuicConnectionRuntimeShardWorkItem(
                entry.Handle,
                entry.Runtime,
                new QuicConnectionTimerExpiredEvent(nowTicks, entry.TimerKind, entry.Generation))))
            {
                break;
            }

            count++;
        }

        return count;
    }

    private bool TryPeekNextValidEntry(out QuicConnectionRuntimeScheduledTimerEntry entry)
    {
        // The heap can contain stale entries after a re-arm or cancellation, so each candidate must be validated
        // against the active registration table before it is treated as live work.
        while (timerHeap.TryPeek(out QuicConnectionRuntimeScheduledTimerEntry candidate, out _))
        {
            QuicConnectionRuntimeScheduledTimerKey key = new(candidate.Handle, candidate.TimerKind);
            if (!registrations.TryGetValue(key, out QuicConnectionRuntimeScheduledTimerRegistration registration)
                || !ReferenceEquals(registration.Runtime, candidate.Runtime)
                || registration.Generation != candidate.Generation
                || registration.DueTicks != candidate.DueTicks)
            {
                timerHeap.Dequeue();
                continue;
            }

            entry = candidate;
            return true;
        }

        entry = default;
        return false;
    }

    private bool CompactStaleEntriesIfNeeded()
    {
        if (timerHeap.Count < StaleTimerHeapCompactionThreshold)
        {
            return false;
        }

        int activeRegistrationCount = registrations.Count;
        long compactionLimit = (long)activeRegistrationCount * StaleTimerHeapCompactionFactor;
        if (activeRegistrationCount > 0
            && timerHeap.Count <= compactionLimit)
        {
            return false;
        }

        PriorityQueue<QuicConnectionRuntimeScheduledTimerEntry, QuicConnectionTimerPriority> compactedHeap =
            activeRegistrationCount == 0
                ? new()
                : new(Math.Max(InitialTimerHeapCapacity, activeRegistrationCount));

        foreach (KeyValuePair<QuicConnectionRuntimeScheduledTimerKey, QuicConnectionRuntimeScheduledTimerRegistration> registrationEntry in registrations)
        {
            QuicConnectionRuntimeScheduledTimerKey key = registrationEntry.Key;
            QuicConnectionRuntimeScheduledTimerRegistration registration = registrationEntry.Value;
            QuicConnectionRuntimeScheduledTimerEntry entry = new(
                key.Handle,
                registration.Runtime,
                key.TimerKind,
                registration.DueTicks,
                registration.Generation,
                registration.Priority);

            compactedHeap.Enqueue(entry, registration.Priority);
        }

        timerHeap = compactedHeap;
        return true;
    }

    private static TimeSpan StopwatchTicksToTimeSpan(long ticks)
    {
        double seconds = ticks / (double)Stopwatch.Frequency;
        if (seconds >= TimeSpan.MaxValue.TotalSeconds)
        {
            return TimeSpan.MaxValue;
        }

        return TimeSpan.FromSeconds(seconds);
    }
}
