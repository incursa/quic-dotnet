// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Reflection;
using System.Threading;

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimeCompletionSourcePoolingTests
{
    [Fact]
    public void CompletionSourcePools_AreTypeLocalAndResetMutableStateOnReuse()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        object streamOpenCompletion = RentCompletionSource(
            runtime,
            "RentStreamOpenRequestCompletionSource",
            QuicStreamType.Bidirectional);
        Assert.Equal(QuicStreamType.Bidirectional, GetPropertyValue<QuicStreamType>(streamOpenCompletion, "StreamType"));
        SetFieldValue(streamOpenCompletion, "completed", 17);
        ReturnCompletionSource(runtime, "ReturnStreamOpenRequestCompletionSource", streamOpenCompletion);

        object streamActionCompletion = RentCompletionSource(runtime, "RentStreamActionRequestCompletionSource");
        Assert.NotSame(streamOpenCompletion, streamActionCompletion);
        InvokeVoidMethod(
            streamActionCompletion,
            "ConfigureWrite",
            QuicConnectionStreamActionKind.Write,
            42UL,
            7);
        SetPropertyValue(streamActionCompletion, "SuppressTerminalException", true);
        SetFieldValue(streamActionCompletion, "completed", 23);
        ReturnCompletionSource(runtime, "ReturnStreamActionRequestCompletionSource", streamActionCompletion);

        object datagramCompletion = RentCompletionSource(runtime, "RentDatagramSendRequestCompletionSource");
        Assert.NotSame(streamOpenCompletion, datagramCompletion);
        Assert.NotSame(streamActionCompletion, datagramCompletion);
        SetFieldValue(datagramCompletion, "completed", 31);
        ReturnCompletionSource(runtime, "ReturnDatagramSendRequestCompletionSource", datagramCompletion);

        object reusedStreamOpenCompletion = RentCompletionSource(
            runtime,
            "RentStreamOpenRequestCompletionSource",
            QuicStreamType.Unidirectional);
        Assert.Same(streamOpenCompletion, reusedStreamOpenCompletion);
        Assert.Equal(QuicStreamType.Unidirectional, GetPropertyValue<QuicStreamType>(reusedStreamOpenCompletion, "StreamType"));
        Assert.Equal(0, GetFieldValue<int>(reusedStreamOpenCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnStreamOpenRequestCompletionSource", reusedStreamOpenCompletion);

        object reusedStreamActionCompletion = RentCompletionSource(runtime, "RentStreamActionRequestCompletionSource");
        Assert.Same(streamActionCompletion, reusedStreamActionCompletion);
        Assert.Equal(default(QuicConnectionStreamActionKind), GetPropertyValue<QuicConnectionStreamActionKind>(reusedStreamActionCompletion, "ActionKind"));
        Assert.Equal(default(ulong), GetPropertyValue<ulong>(reusedStreamActionCompletion, "StreamId"));
        Assert.Equal(0, GetPropertyValue<int>(reusedStreamActionCompletion, "StreamDataLength"));
        Assert.False(GetPropertyValue<bool>(reusedStreamActionCompletion, "SuppressTerminalException"));
        Assert.Equal(0, GetFieldValue<int>(reusedStreamActionCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnStreamActionRequestCompletionSource", reusedStreamActionCompletion);

        object reusedDatagramCompletion = RentCompletionSource(runtime, "RentDatagramSendRequestCompletionSource");
        Assert.Same(datagramCompletion, reusedDatagramCompletion);
        Assert.Equal(0, GetFieldValue<int>(reusedDatagramCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnDatagramSendRequestCompletionSource", reusedDatagramCompletion);
    }

    [Fact]
    public async Task CompletionSourcePools_AreIsolatedUnderParallelRentAndReturn()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        await Task.WhenAll(
            ExerciseStreamOpenRequestCompletionSourcePoolAsync(runtime),
            ExerciseStreamActionRequestCompletionSourcePoolAsync(runtime),
            ExerciseDatagramSendRequestCompletionSourcePoolAsync(runtime)).WaitAsync(TimeSpan.FromSeconds(30));

        object streamOpenCompletion = RentCompletionSource(
            runtime,
            "RentStreamOpenRequestCompletionSource",
            QuicStreamType.Bidirectional);
        Assert.Equal(QuicStreamType.Bidirectional, GetPropertyValue<QuicStreamType>(streamOpenCompletion, "StreamType"));
        Assert.Equal(0, GetFieldValue<int>(streamOpenCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnStreamOpenRequestCompletionSource", streamOpenCompletion);

        object streamActionCompletion = RentCompletionSource(runtime, "RentStreamActionRequestCompletionSource");
        Assert.Equal(default(QuicConnectionStreamActionKind), GetPropertyValue<QuicConnectionStreamActionKind>(streamActionCompletion, "ActionKind"));
        Assert.Equal(default(ulong), GetPropertyValue<ulong>(streamActionCompletion, "StreamId"));
        Assert.Equal(0, GetPropertyValue<int>(streamActionCompletion, "StreamDataLength"));
        Assert.False(GetPropertyValue<bool>(streamActionCompletion, "SuppressTerminalException"));
        Assert.Equal(0, GetFieldValue<int>(streamActionCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnStreamActionRequestCompletionSource", streamActionCompletion);

        object datagramCompletion = RentCompletionSource(runtime, "RentDatagramSendRequestCompletionSource");
        Assert.Equal(0, GetFieldValue<int>(datagramCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnDatagramSendRequestCompletionSource", datagramCompletion);
    }

    [Fact]
    public async Task CompletionSourcePools_ResetCleanlyAcrossCompletionRaces()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        object streamOpenCompletion = RentCompletionSource(runtime, "RentStreamOpenRequestCompletionSource", QuicStreamType.Bidirectional);
        ValueTask<QuicStream> streamOpenTask = GetPropertyValue<ValueTask<QuicStream>>(streamOpenCompletion, "Task");
        await RunRacedActionsAsync(
            () => InvokeVoidMethod(streamOpenCompletion, "TrySetResult", 7UL),
            () => InvokeVoidMethod(streamOpenCompletion, "TrySetException", new InvalidOperationException("open-fault")),
            () => InvokeVoidMethod(streamOpenCompletion, "TrySetCanceled", new CancellationToken(canceled: true))).WaitAsync(TimeSpan.FromSeconds(10));

        Exception? streamOpenException = await Record.ExceptionAsync(async () => await streamOpenTask.ConfigureAwait(false));
        Assert.True(streamOpenException is null or InvalidOperationException or OperationCanceledException);

        object reusedStreamOpenCompletion = RentCompletionSource(runtime, "RentStreamOpenRequestCompletionSource", QuicStreamType.Unidirectional);
        Assert.Same(streamOpenCompletion, reusedStreamOpenCompletion);
        Assert.Equal(QuicStreamType.Unidirectional, GetPropertyValue<QuicStreamType>(reusedStreamOpenCompletion, "StreamType"));
        Assert.Equal(0, GetFieldValue<int>(reusedStreamOpenCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnStreamOpenRequestCompletionSource", reusedStreamOpenCompletion);

        object streamActionCompletion = RentCompletionSource(runtime, "RentStreamActionRequestCompletionSource");
        SetPropertyValue(streamActionCompletion, "SuppressTerminalException", true);
        ValueTask<bool> streamActionTask = GetPropertyValue<ValueTask<bool>>(streamActionCompletion, "Task");
        await RunRacedActionsAsync(
            () => InvokeVoidMethod(streamActionCompletion, "TrySetResult"),
            () => InvokeVoidMethod(streamActionCompletion, "TrySetException", new InvalidOperationException("write-fault")),
            () => InvokeVoidMethod(streamActionCompletion, "TrySetTerminalException", new InvalidOperationException("terminal-fault")),
            () => InvokeVoidMethod(streamActionCompletion, "TrySetCanceled", new CancellationToken(canceled: true))).WaitAsync(TimeSpan.FromSeconds(10));

        Exception? streamActionException = await Record.ExceptionAsync(async () => _ = await streamActionTask.ConfigureAwait(false));
        Assert.True(streamActionException is null or InvalidOperationException or OperationCanceledException);

        object reusedStreamActionCompletion = RentCompletionSource(runtime, "RentStreamActionRequestCompletionSource");
        Assert.Same(streamActionCompletion, reusedStreamActionCompletion);
        Assert.Equal(default(QuicConnectionStreamActionKind), GetPropertyValue<QuicConnectionStreamActionKind>(reusedStreamActionCompletion, "ActionKind"));
        Assert.Equal(default(ulong), GetPropertyValue<ulong>(reusedStreamActionCompletion, "StreamId"));
        Assert.Equal(0, GetPropertyValue<int>(reusedStreamActionCompletion, "StreamDataLength"));
        Assert.False(GetPropertyValue<bool>(reusedStreamActionCompletion, "SuppressTerminalException"));
        Assert.Equal(0, GetFieldValue<int>(reusedStreamActionCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnStreamActionRequestCompletionSource", reusedStreamActionCompletion);

        object datagramCompletion = RentCompletionSource(runtime, "RentDatagramSendRequestCompletionSource");
        ValueTask datagramTask = GetPropertyValue<ValueTask>(datagramCompletion, "Task");
        await RunRacedActionsAsync(
            () => InvokeVoidMethod(datagramCompletion, "TrySetResult"),
            () => InvokeVoidMethod(datagramCompletion, "TrySetException", new InvalidOperationException("datagram-fault")),
            () => InvokeVoidMethod(datagramCompletion, "TrySetCanceled", new CancellationToken(canceled: true))).WaitAsync(TimeSpan.FromSeconds(10));

        Exception? datagramException = await Record.ExceptionAsync(async () => await datagramTask.ConfigureAwait(false));
        Assert.True(datagramException is null or InvalidOperationException or OperationCanceledException);

        object reusedDatagramCompletion = RentCompletionSource(runtime, "RentDatagramSendRequestCompletionSource");
        Assert.Same(datagramCompletion, reusedDatagramCompletion);
        Assert.Equal(0, GetFieldValue<int>(reusedDatagramCompletion, "completed"));
        ReturnCompletionSource(runtime, "ReturnDatagramSendRequestCompletionSource", reusedDatagramCompletion);
    }

    private static object RentCompletionSource(QuicConnectionRuntime runtime, string methodName, params object?[] arguments)
    {
        return InvokeObjectMethod(runtime, methodName, arguments)
            ?? throw new InvalidOperationException($"{methodName} returned null.");
    }

    private static void ReturnCompletionSource(QuicConnectionRuntime runtime, string methodName, object completionSource)
    {
        InvokeVoidMethod(runtime, methodName, completionSource);
    }

    private static object? InvokeObjectMethod(object instance, string methodName, params object?[] arguments)
    {
        MethodInfo method = instance.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Could not find {methodName}.");

        return method.Invoke(instance, arguments);
    }

    private static void InvokeVoidMethod(object instance, string methodName, params object?[] arguments)
    {
        MethodInfo[] matchingMethods = instance.GetType()
            .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic)
            .Where(candidate => string.Equals(candidate.Name, methodName, StringComparison.Ordinal))
            .Where(candidate =>
            {
                ParameterInfo[] candidateParameters = candidate.GetParameters();
                return arguments.Length <= candidateParameters.Length
                    && candidateParameters
                        .Take(arguments.Length)
                        .Select((parameter, index) => (parameter, argument: arguments[index]))
                        .All(item => item.argument is null
                            ? !item.parameter.ParameterType.IsValueType
                                || Nullable.GetUnderlyingType(item.parameter.ParameterType) is not null
                            : item.parameter.ParameterType.IsInstanceOfType(item.argument))
                    && candidateParameters.Skip(arguments.Length).All(parameter => parameter.IsOptional);
            })
            .ToArray();

        MethodInfo method = matchingMethods.Length == 1
            ? matchingMethods[0]
            : throw new InvalidOperationException(
                $"Expected one compatible {methodName} overload, but found {matchingMethods.Length}.");

        ParameterInfo[] parameters = method.GetParameters();
        if (arguments.Length < parameters.Length)
        {
            object?[] completedArguments = new object?[parameters.Length];
            arguments.CopyTo(completedArguments, 0);
            for (int index = arguments.Length; index < parameters.Length; index++)
            {
                if (!parameters[index].IsOptional)
                {
                    throw new TargetParameterCountException(
                        $"{methodName} requires {parameters.Length} arguments.");
                }

                completedArguments[index] = Type.Missing;
            }

            arguments = completedArguments;
        }

        _ = method.Invoke(instance, arguments);
    }

    private static T GetPropertyValue<T>(object instance, string propertyName)
    {
        PropertyInfo property = instance.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Could not find property {propertyName}.");

        return (T)(property.GetValue(instance)
            ?? throw new InvalidOperationException($"Property {propertyName} returned null."));
    }

    private static void SetPropertyValue(object instance, string propertyName, object? value)
    {
        PropertyInfo property = instance.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Could not find property {propertyName}.");

        property.SetValue(instance, value);
    }

    private static T GetFieldValue<T>(object instance, string fieldName)
    {
        FieldInfo field = instance.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Could not find field {fieldName}.");

        return (T)(field.GetValue(instance)
            ?? throw new InvalidOperationException($"Field {fieldName} returned null."));
    }

    private static void SetFieldValue(object instance, string fieldName, object? value)
    {
        FieldInfo field = instance.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Could not find field {fieldName}.");

        field.SetValue(instance, value);
    }

    private static async Task RunRacedActionsAsync(params Action[] actions)
    {
        using ManualResetEventSlim startGate = new(false);
        Task[] workers = actions
            .Select(action => Task.Run(() =>
            {
                startGate.Wait();
                action();
            }))
            .ToArray();

        startGate.Set();
        await Task.WhenAll(workers).ConfigureAwait(false);
    }

    private static Task ExerciseStreamOpenRequestCompletionSourcePoolAsync(QuicConnectionRuntime runtime)
    {
        return RunConcurrentWorkersAsync(4, 64, (workerIndex, iteration) =>
        {
            QuicStreamType streamType = ((workerIndex + iteration) & 1) == 0
                ? QuicStreamType.Bidirectional
                : QuicStreamType.Unidirectional;

            object completion = RentCompletionSource(runtime, "RentStreamOpenRequestCompletionSource", streamType);
            try
            {
                Assert.Equal(streamType, GetPropertyValue<QuicStreamType>(completion, "StreamType"));
                Assert.Equal(0, GetFieldValue<int>(completion, "completed"));
                SetFieldValue(completion, "completed", workerIndex * 1000 + iteration + 1);
            }
            finally
            {
                ReturnCompletionSource(runtime, "ReturnStreamOpenRequestCompletionSource", completion);
            }
        });
    }

    private static Task ExerciseStreamActionRequestCompletionSourcePoolAsync(QuicConnectionRuntime runtime)
    {
        return RunConcurrentWorkersAsync(4, 64, (workerIndex, iteration) =>
        {
            object completion = RentCompletionSource(runtime, "RentStreamActionRequestCompletionSource");
            try
            {
                Assert.Equal(default(QuicConnectionStreamActionKind), GetPropertyValue<QuicConnectionStreamActionKind>(completion, "ActionKind"));
                Assert.Equal(default(ulong), GetPropertyValue<ulong>(completion, "StreamId"));
                Assert.Equal(0, GetPropertyValue<int>(completion, "StreamDataLength"));
                Assert.False(GetPropertyValue<bool>(completion, "SuppressTerminalException"));
                Assert.Equal(0, GetFieldValue<int>(completion, "completed"));

                SetPropertyValue(completion, "SuppressTerminalException", true);
                InvokeVoidMethod(
                    completion,
                    "ConfigureWrite",
                    (iteration & 1) == 0 ? QuicConnectionStreamActionKind.Write : QuicConnectionStreamActionKind.Finish,
                    (ulong)((workerIndex + 1) * 100 + iteration),
                    iteration + 1);
                SetFieldValue(completion, "completed", workerIndex * 1000 + iteration + 1);
            }
            finally
            {
                ReturnCompletionSource(runtime, "ReturnStreamActionRequestCompletionSource", completion);
            }
        });
    }

    private static Task ExerciseDatagramSendRequestCompletionSourcePoolAsync(QuicConnectionRuntime runtime)
    {
        return RunConcurrentWorkersAsync(4, 64, (workerIndex, iteration) =>
        {
            object completion = RentCompletionSource(runtime, "RentDatagramSendRequestCompletionSource");
            try
            {
                Assert.Equal(0, GetFieldValue<int>(completion, "completed"));
                SetFieldValue(completion, "completed", workerIndex * 1000 + iteration + 1);
            }
            finally
            {
                ReturnCompletionSource(runtime, "ReturnDatagramSendRequestCompletionSource", completion);
            }
        });
    }

    private static async Task RunConcurrentWorkersAsync(int workerCount, int iterations, Action<int, int> body)
    {
        using ManualResetEventSlim startGate = new(false);
        Task[] workers = Enumerable.Range(0, workerCount)
            .Select(workerIndex => Task.Run(() =>
            {
                startGate.Wait();
                for (int iteration = 0; iteration < iterations; iteration++)
                {
                    body(workerIndex, iteration);
                }
            }))
            .ToArray();

        startGate.Set();
        await Task.WhenAll(workers).ConfigureAwait(false);
    }
}
