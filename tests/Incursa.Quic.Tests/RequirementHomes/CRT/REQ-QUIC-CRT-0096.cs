// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0096")]
public sealed class REQ_QUIC_CRT_0096
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeConcurrentCollectionsAreLimitedToCrossThreadApiRequestState()
    {
        // Quarantined structural probe: follow-up work item will replace this reflection-based
        // field-shape check with a non-reflection repository-native assertion.
        FieldInfo[] runtimeFields = typeof(QuicConnectionRuntime)
            .GetFields(BindingFlags.Instance | BindingFlags.NonPublic);

        string[] concurrentFieldNames = runtimeFields
            .Where(field => IsConcurrentDictionary(field.FieldType))
            .Select(field => field.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [
                "pendingDatagramSendRequests",
                "pendingStreamOpenRequests",
            ],
            concurrentFieldNames);
        Assert.Equal(
            typeof(QuicStreamObserverDirectory),
            Assert.Single(runtimeFields, field => field.Name == "streamObservers").FieldType);
    }

    private static bool IsConcurrentDictionary(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ConcurrentDictionary<,>);
    }
}
