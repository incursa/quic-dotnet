using System.Collections.Concurrent;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0014")]
public sealed class REQ_QUIC_CRT_0014
{
    private static readonly string[] EndpointRouteAndTokenRegistryFields =
    [
        "routeIdsByHandle",
        "routesByLength",
        "statelessResetConnectionIdsByRouteIdByHandle",
        "statelessResetTokenIdsByHandle",
        "statelessResetBindingsByMatchKey",
        "statelessResetBindingsByConnectionId",
        "retainedStatelessResetBindingsByRouteLength",
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointSharedRouteAndTokenRegistriesUseConcurrentDictionaries()
    {
        foreach (string fieldName in EndpointRouteAndTokenRegistryFields)
        {
            FieldInfo? field = typeof(QuicConnectionRuntimeEndpoint).GetField(
                fieldName,
                BindingFlags.Instance | BindingFlags.NonPublic);

            Assert.NotNull(field);
            Assert.True(
                IsConcurrentDictionary(field!.FieldType),
                $"{fieldName} must remain an endpoint-scoped concurrent registry.");
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointSharedRouteAndTokenRegistriesDoNotMoveIntoConnectionRuntime()
    {
        foreach (string fieldName in EndpointRouteAndTokenRegistryFields)
        {
            FieldInfo? runtimeField = typeof(QuicConnectionRuntime).GetField(
                fieldName,
                BindingFlags.Instance | BindingFlags.NonPublic);

            Assert.Null(runtimeField);
        }

        FieldInfo? connectionOwnedTokenMemory = typeof(QuicConnectionRuntime).GetField(
            "statelessResetTokensByConnectionId",
            BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(connectionOwnedTokenMemory);
        Assert.False(IsConcurrentDictionary(connectionOwnedTokenMemory!.FieldType));
    }

    private static bool IsConcurrentDictionary(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ConcurrentDictionary<,>);
    }
}
