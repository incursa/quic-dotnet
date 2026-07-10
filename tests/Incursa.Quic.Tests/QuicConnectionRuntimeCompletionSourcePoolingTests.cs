// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Reflection;

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
        MethodInfo method = instance.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Could not find {methodName}.");

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
}
