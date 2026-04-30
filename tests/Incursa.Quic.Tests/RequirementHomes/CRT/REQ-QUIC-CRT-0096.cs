using System.Collections.Concurrent;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0096")]
public sealed class REQ_QUIC_CRT_0096
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeConcurrentCollectionsAreLimitedToApiQueuesAndObservers()
    {
        string[] concurrentFieldNames = typeof(QuicConnectionRuntime)
            .GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
            .Where(field => IsConcurrentDictionary(field.FieldType))
            .Select(field => field.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [
                "pendingStreamActionRequests",
                "pendingStreamOpenRequests",
                "pendingStreamOpenTypes",
                "streamObservers",
            ],
            concurrentFieldNames);
    }

    private static bool IsConcurrentDictionary(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ConcurrentDictionary<,>);
    }
}
