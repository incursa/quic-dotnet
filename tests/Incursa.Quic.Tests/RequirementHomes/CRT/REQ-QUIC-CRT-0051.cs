// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0051")]
public sealed class REQ_QUIC_CRT_0051
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionRuntimeDoesNotOwnPerConnectionTimerInstances()
    {
        // Quarantined structural probe: follow-up work item will replace this reflection-based
        // field-shape check with a non-reflection repository-native assertion.
        FieldInfo[] timerFields = typeof(QuicConnectionRuntime)
            .GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(field =>
                field.FieldType == typeof(Timer)
                || field.FieldType == typeof(PeriodicTimer)
                || field.FieldType == typeof(System.Timers.Timer))
            .ToArray();

        Assert.Empty(timerFields);
    }
}
