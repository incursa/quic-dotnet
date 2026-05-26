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
        // Quarantined structural probe: follow-up work item will replace this reflection-based
        // field-shape check with a non-reflection repository-native assertion.
        string[] concurrentFieldNames = typeof(QuicConnectionRuntime)
            .GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
            .Where(field => IsConcurrentDictionary(field.FieldType))
            .Select(field => field.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [
                "pendingDatagramSendRequests",
                "pendingStreamActionRequests",
                "pendingStreamOpenRequests",
                "pendingStreamOpenTypes",
                "queuedInboundStreamIds",
                "streamObservers",
            ],
            concurrentFieldNames);
    }

    private static bool IsConcurrentDictionary(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ConcurrentDictionary<,>);
    }
}
