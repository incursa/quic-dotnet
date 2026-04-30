using System.Collections.Concurrent;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0010")]
public sealed class REQ_QUIC_CRT_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PathLifecycleTimerAndStreamStateFieldsDoNotUseConcurrentCollections()
    {
        string[] connectionOwnedStateFields =
        [
            "candidatePaths",
            "recentlyValidatedPaths",
            "statelessResetTokensByConnectionId",
            "newTokenEmissionsByRemoteAddress",
            "bufferedEstablishmentHandshakePackets",
            "streamRegistry",
            "timerState",
            "terminalState",
            "idleTimeoutState",
        ];

        foreach (string fieldName in connectionOwnedStateFields)
        {
            FieldInfo? field = typeof(QuicConnectionRuntime).GetField(
                fieldName,
                BindingFlags.Instance | BindingFlags.NonPublic);

            Assert.NotNull(field);
            Assert.False(IsConcurrentCollection(field!.FieldType), $"{fieldName} must remain connection-owned ordinary state.");
        }
    }

    private static bool IsConcurrentCollection(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ConcurrentDictionary<,>);
    }
}
