// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using System.Threading.Tasks.Sources;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks runtime request-completion primitives used by local API queues.
/// </summary>
[MemoryDiagnoser]
public class QuicRuntimeRequestCompletionSourceBenchmarks
{
    private readonly ConcurrentQueue<PooledOpenCompletionSource> openPool = new();
    private readonly ConcurrentQueue<PooledVoidCompletionSource> voidPool = new();

    /// <summary>
    /// Measures the prior stream-open request completion shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public ulong TaskCompletionSourceStreamOpen()
    {
        TaskCompletionSource<ulong> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<ulong> task = completion.Task;
        completion.SetResult(42);
        return task.GetAwaiter().GetResult();
    }

    /// <summary>
    /// Measures stream-open request completion with a pooled value-task source.
    /// </summary>
    [Benchmark]
    public ulong PooledValueTaskSourceStreamOpen()
    {
        PooledOpenCompletionSource completion = RentOpenCompletionSource();
        ValueTask<ulong> task = completion.Task;
        completion.SetResult(42);
        return task.GetAwaiter().GetResult();
    }

    /// <summary>
    /// Measures the prior DATAGRAM send request completion shape.
    /// </summary>
    [Benchmark]
    public void TaskCompletionSourceDatagramSend()
    {
        TaskCompletionSource<object?> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task task = completion.Task;
        completion.SetResult(null);
        task.GetAwaiter().GetResult();
    }

    /// <summary>
    /// Measures DATAGRAM send request completion with a pooled value-task source.
    /// </summary>
    [Benchmark]
    public void PooledValueTaskSourceDatagramSend()
    {
        PooledVoidCompletionSource completion = RentVoidCompletionSource();
        ValueTask task = completion.Task;
        completion.SetResult();
        task.GetAwaiter().GetResult();
    }

    private PooledOpenCompletionSource RentOpenCompletionSource()
    {
        if (!openPool.TryDequeue(out PooledOpenCompletionSource? completion))
        {
            completion = new PooledOpenCompletionSource(openPool);
        }

        completion.Prepare();
        return completion;
    }

    private PooledVoidCompletionSource RentVoidCompletionSource()
    {
        if (!voidPool.TryDequeue(out PooledVoidCompletionSource? completion))
        {
            completion = new PooledVoidCompletionSource(voidPool);
        }

        completion.Prepare();
        return completion;
    }

    private sealed class PooledOpenCompletionSource(ConcurrentQueue<PooledOpenCompletionSource> owner)
        : IValueTaskSource<ulong>
    {
        private ManualResetValueTaskSourceCore<ulong> source = new()
        {
            RunContinuationsAsynchronously = true,
        };

        internal ValueTask<ulong> Task => new(this, source.Version);

        internal void Prepare()
        {
            source.Reset();
        }

        internal void SetResult(ulong value)
        {
            source.SetResult(value);
        }

        ulong IValueTaskSource<ulong>.GetResult(short token)
        {
            try
            {
                return source.GetResult(token);
            }
            finally
            {
                owner.Enqueue(this);
            }
        }

        ValueTaskSourceStatus IValueTaskSource<ulong>.GetStatus(short token)
            => source.GetStatus(token);

        void IValueTaskSource<ulong>.OnCompleted(
            Action<object?> continuation,
            object? state,
            short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            source.OnCompleted(continuation, state, token, flags);
        }
    }

    private sealed class PooledVoidCompletionSource(ConcurrentQueue<PooledVoidCompletionSource> owner)
        : IValueTaskSource
    {
        private ManualResetValueTaskSourceCore<bool> source = new()
        {
            RunContinuationsAsynchronously = true,
        };

        internal ValueTask Task => new(this, source.Version);

        internal void Prepare()
        {
            source.Reset();
        }

        internal void SetResult()
        {
            source.SetResult(true);
        }

        void IValueTaskSource.GetResult(short token)
        {
            try
            {
                _ = source.GetResult(token);
            }
            finally
            {
                owner.Enqueue(this);
            }
        }

        ValueTaskSourceStatus IValueTaskSource.GetStatus(short token)
            => source.GetStatus(token);

        void IValueTaskSource.OnCompleted(
            Action<object?> continuation,
            object? state,
            short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            source.OnCompleted(continuation, state, token, flags);
        }
    }
}
