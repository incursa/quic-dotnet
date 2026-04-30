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
