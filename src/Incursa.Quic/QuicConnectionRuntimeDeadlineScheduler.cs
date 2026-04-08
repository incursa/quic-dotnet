using System.Diagnostics;
using System.Threading.Channels;

namespace Incursa.Quic;

internal sealed class QuicConnectionRuntimeDeadlineScheduler
{
    private readonly PriorityQueue<QuicConnectionRuntimeScheduledTimerEntry, QuicConnectionTimerPriority> timerHeap = new();
    private readonly Dictionary<QuicConnectionRuntimeScheduledTimerKey, QuicConnectionRuntimeScheduledTimerRegistration> registrations = [];

    public int RegistrationCount => registrations.Count;

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
            effect.Generation);

        registrations[key] = registration;

        QuicConnectionRuntimeScheduledTimerEntry entry = new(
            handle,
            runtime,
            effect.TimerKind,
            effect.Priority.DueTicks,
            effect.Generation,
            effect.Priority);

        timerHeap.Enqueue(entry, effect.Priority);
    }

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
    }

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
