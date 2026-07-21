// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0168")]
public sealed class REQ_QUIC_CRT_0168
{
    private static readonly string[] OfflineOnlyNames =
    [
        "ScenarioId",
        "TrafficShape",
        "PayloadBytes",
        "AccountingMode",
        "RequestedConnections",
        "EffectiveConnections",
        "RequestedStreamsPerConnection",
        "EffectiveStreamsPerConnection",
        "RequestedConcurrency",
        "EffectiveConcurrency",
        "BenchmarkLabel",
        "OnlineLearningOutput",
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeObservationExcludesOfflineOnlyWorkloadIdentity()
    {
        HashSet<string> observationProperties = typeof(QuicAdaptiveRuntimeConnectionObservation)
            .GetProperties()
            .Select(static property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        foreach (string offlineOnlyName in OfflineOnlyNames)
        {
            Assert.DoesNotContain(offlineOnlyName, observationProperties);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShadowEvaluationAcceptsOnlyTheVersionedConnectionObservation()
    {
        Type[] parameterTypes = typeof(QuicReceiveCreditShadowController)
            .GetMethod("TryEvaluate", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetParameters()
            .Select(static parameter => parameter.ParameterType.IsByRef
                ? parameter.ParameterType.GetElementType()!
                : parameter.ParameterType)
            .ToArray();

        Assert.Equal(
            [typeof(QuicAdaptiveRuntimeConnectionObservation), typeof(QuicReceiveCreditPolicySnapshot)],
            parameterTypes);
    }
}
