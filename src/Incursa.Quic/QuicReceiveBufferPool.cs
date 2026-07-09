// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal sealed class QuicReceiveBufferPool : IDisposable
{
    // CONTEXT: receive buffers use a bounded ring fast path with ArrayPool fallback
    // SEE: code:src/Incursa.Quic/QuicReceiveBufferPool.cs#Rent
    // SEE: code:src/Incursa.Quic/QuicReceiveBufferPool.cs#Return
    // The ring keeps the common receive path allocation-free while the
    // fallback preserves progress when the ring is exhausted. The default ring
    // size is intentionally environment-tunable for diagnostics without
    // changing the ownership model.
    internal const int DefaultRingSize = 128;
    internal const string RingSizeEnvironmentVariable = "INCURSA_QUIC_RECEIVE_BUFFER_RING_SIZE";

    private static int nextPoolId;
    private readonly object gate = new();
    private readonly byte[]?[] ringBuffers;
    private readonly int[] freeIndexes;
    private readonly bool[] rentedRingBuffers;
    private readonly Dictionary<byte[], int> ringIndexes;
    private readonly int bufferSize;
    private readonly int poolId;
    private readonly string ownerName;

    private int freeCount;
    private long currentOutstanding;
    private long maxOutstanding;
    private long ringRents;
    private long fallbackRents;
    private long returns;
    private long doubleReturnAttempts;
    private long allocatedRingBuffers;
    private int disposed;

    internal QuicReceiveBufferPool(
        int bufferSize,
        int? ringSize = null,
        string ownerName = "unknown",
        bool preallocateRingBuffers = false)
    {
        if (bufferSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bufferSize));
        }

        int effectiveRingSize = ringSize ?? ResolveDefaultRingSize();
        if (effectiveRingSize < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ringSize));
        }

        this.bufferSize = bufferSize;
        this.ownerName = string.IsNullOrWhiteSpace(ownerName) ? "unknown" : ownerName;
        poolId = Interlocked.Increment(ref nextPoolId);
        ringBuffers = new byte[effectiveRingSize][];
        freeIndexes = new int[effectiveRingSize];
        rentedRingBuffers = new bool[effectiveRingSize];
        ringIndexes = new Dictionary<byte[], int>(effectiveRingSize, ReferenceEqualityComparer.Instance);

        for (int index = 0; index < effectiveRingSize; index++)
        {
            freeIndexes[index] = index;
        }

        freeCount = effectiveRingSize;
        if (preallocateRingBuffers)
        {
            PreallocateRingBuffers();
        }

        QuicReceiveBufferPoolDiagnostics.Register(this);
    }

    internal QuicReceiveBufferPoolSnapshot Snapshot => new(
        poolId,
        ownerName,
        bufferSize,
        ringBuffers.Length,
        Volatile.Read(ref currentOutstanding),
        Volatile.Read(ref maxOutstanding),
        Volatile.Read(ref ringRents),
        Volatile.Read(ref fallbackRents),
        Volatile.Read(ref returns),
        Volatile.Read(ref doubleReturnAttempts),
        Volatile.Read(ref allocatedRingBuffers));

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        QuicReceiveBufferPoolDiagnostics.EmitSnapshot(this, "dispose");
        QuicReceiveBufferPoolDiagnostics.Unregister(this);
    }

    internal QuicReceiveBufferLease Rent()
    {
        lock (gate)
        {
            if (freeCount > 0)
            {
                int index = freeIndexes[--freeCount];
                byte[]? buffer = ringBuffers[index];
                if (buffer is null)
                {
                    buffer = AllocateRingBuffer(index);
                }

                rentedRingBuffers[index] = true;
                RecordRent(ring: true);
                return new QuicReceiveBufferLease(this, buffer, bufferSize, fromRing: true);
            }
        }

        byte[] fallbackBuffer = QuicBufferPool.RentBytes(bufferSize);
        RecordRent(ring: false);
        return new QuicReceiveBufferLease(this, fallbackBuffer, bufferSize, fromRing: false);
    }

    internal void Return(byte[] buffer, QuicReceiveBufferOwnership ownership)
    {
        if (!ReferenceEquals(ownership.Pool, this))
        {
            QuicBufferPool.ReturnBytes(buffer);
            RecordReturn();
            return;
        }

        if (!ownership.FromRing)
        {
            QuicBufferPool.ReturnBytes(buffer);
            RecordReturn();
            return;
        }

        lock (gate)
        {
            if (!ringIndexes.TryGetValue(buffer, out int index) || !rentedRingBuffers[index])
            {
                Interlocked.Increment(ref doubleReturnAttempts);
                return;
            }

            rentedRingBuffers[index] = false;
            freeIndexes[freeCount++] = index;
        }

        RecordReturn();
    }

    private void PreallocateRingBuffers()
    {
        for (int index = 0; index < ringBuffers.Length; index++)
        {
            _ = AllocateRingBuffer(index);
        }
    }

    private byte[] AllocateRingBuffer(int index)
    {
        byte[] buffer = new byte[bufferSize];
        ringBuffers[index] = buffer;
        ringIndexes.Add(buffer, index);
        Interlocked.Increment(ref allocatedRingBuffers);
        return buffer;
    }

    private void RecordRent(bool ring)
    {
        if (ring)
        {
            Interlocked.Increment(ref ringRents);
        }
        else
        {
            Interlocked.Increment(ref fallbackRents);
        }

        long outstanding = Interlocked.Increment(ref currentOutstanding);
        while (true)
        {
            long observedMax = Volatile.Read(ref maxOutstanding);
            if (outstanding <= observedMax
                || Interlocked.CompareExchange(ref maxOutstanding, outstanding, observedMax) == observedMax)
            {
                break;
            }
        }
    }

    private void RecordReturn()
    {
        Interlocked.Increment(ref returns);
        Interlocked.Decrement(ref currentOutstanding);
    }

    private static int ResolveDefaultRingSize()
    {
        string? value = Environment.GetEnvironmentVariable(RingSizeEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(value))
        {
            return DefaultRingSize;
        }

        return int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int parsed)
            && parsed >= 0
            ? parsed
            : DefaultRingSize;
    }
}

internal struct QuicReceiveBufferLease : IDisposable
{
    private QuicReceiveBufferPool? pool;
    private byte[]? buffer;
    private int length;
    private bool fromRing;

    internal QuicReceiveBufferLease(QuicReceiveBufferPool pool, byte[] buffer, int length, bool fromRing)
    {
        this.pool = pool;
        this.buffer = buffer;
        this.length = length;
        this.fromRing = fromRing;
    }

    internal byte[] Buffer => buffer ?? throw new ObjectDisposedException(nameof(QuicReceiveBufferLease));

    internal Memory<byte> Memory => buffer is null
        ? Memory<byte>.Empty
        : buffer.AsMemory(0, length);

    internal QuicReceiveBufferOwnership Ownership => new(pool, fromRing);

    internal void TransferToRuntime()
    {
        if (buffer is null)
        {
            throw new ObjectDisposedException(nameof(QuicReceiveBufferLease));
        }

        buffer = null;
        pool = null;
        length = 0;
        fromRing = false;
    }

    public void Dispose()
    {
        byte[]? leasedBuffer = buffer;
        QuicReceiveBufferPool? owner = pool;
        if (leasedBuffer is null || owner is null)
        {
            return;
        }

        buffer = null;
        pool = null;
        length = 0;
        bool returnedFromRing = fromRing;
        fromRing = false;
        owner.Return(leasedBuffer, new QuicReceiveBufferOwnership(owner, returnedFromRing));
    }
}

internal readonly record struct QuicReceiveBufferOwnership(QuicReceiveBufferPool? Pool, bool FromRing);

internal readonly record struct QuicReceiveBufferPoolSnapshot(
    int PoolId,
    string OwnerName,
    int BufferSize,
    int RingSize,
    long CurrentOutstanding,
    long MaxOutstanding,
    long RingRents,
    long FallbackRents,
    long Returns,
    long DoubleReturnAttempts,
    long AllocatedRingBuffers);

internal static class QuicReceiveBufferPoolDiagnostics
{
    internal const string SnapshotPathEnvironmentVariable = "INCURSA_QUIC_RECEIVE_BUFFER_DIAGNOSTICS_PATH";

    private static readonly object gate = new();
    private static readonly List<QuicReceiveBufferPool> Pools = [];
    private static int samplerStarted;

    static QuicReceiveBufferPoolDiagnostics()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) => EmitProcessExitSnapshots();
    }

    internal static void Register(QuicReceiveBufferPool pool)
    {
        lock (gate)
        {
            Pools.Add(pool);
        }

        EnsureSamplerStarted();
    }

    internal static void Unregister(QuicReceiveBufferPool pool)
    {
        lock (gate)
        {
            Pools.Remove(pool);
        }
    }

    internal static void EmitSnapshot(QuicReceiveBufferPool pool, string reason)
    {
        string? path = Environment.GetEnvironmentVariable(SnapshotPathEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        QuicReceiveBufferPoolSnapshot snapshot = pool.Snapshot;
        string directory = Path.GetDirectoryName(path) ?? "";
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        string line = string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $$"""{"timestampUtc":"{{DateTimeOffset.UtcNow:O}}","processId":{{Environment.ProcessId}},"reason":"{{reason}}","poolId":{{snapshot.PoolId}},"ownerName":"{{Escape(snapshot.OwnerName)}}","bufferSize":{{snapshot.BufferSize}},"ringSize":{{snapshot.RingSize}},"allocatedRingBuffers":{{snapshot.AllocatedRingBuffers}},"currentOutstanding":{{snapshot.CurrentOutstanding}},"maxOutstanding":{{snapshot.MaxOutstanding}},"ringRents":{{snapshot.RingRents}},"fallbackRents":{{snapshot.FallbackRents}},"returns":{{snapshot.Returns}},"doubleReturnAttempts":{{snapshot.DoubleReturnAttempts}}}""");

        lock (gate)
        {
            using FileStream stream = new(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using StreamWriter writer = new(stream);
            writer.WriteLine(line);
        }
    }

    private static void EmitProcessExitSnapshots()
    {
        EmitProcessSnapshots("process-exit");
    }

    private static void EnsureSamplerStarted()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(SnapshotPathEnvironmentVariable)) ||
            Interlocked.Exchange(ref samplerStarted, 1) != 0)
        {
            return;
        }

        _ = Task.Run(SampleAsync);
    }

    private static async Task SampleAsync()
    {
        while (!Environment.HasShutdownStarted)
        {
            await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            EmitProcessSnapshots("sample");
        }
    }

    private static void EmitProcessSnapshots(string reason)
    {
        QuicReceiveBufferPool[] pools;
        lock (gate)
        {
            pools = [.. Pools];
        }

        foreach (QuicReceiveBufferPool pool in pools)
        {
            EmitSnapshot(pool, reason);
        }
    }

    private static string Escape(string value)
        => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
}
