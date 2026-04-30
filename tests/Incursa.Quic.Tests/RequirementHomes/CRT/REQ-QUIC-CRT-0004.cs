using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0004")]
public sealed class REQ_QUIC_CRT_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnectionRuntimeIsTheOnlyTransitionOrchestrationSurface()
    {
        MethodInfo[] transitionMethods = typeof(QuicConnectionRuntime)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(method => method.Name == nameof(QuicConnectionRuntime.Transition))
            .ToArray();

        Assert.Equal(2, transitionMethods.Length);

        Type[] otherTypesWithConnectionEventTransition = typeof(QuicConnectionRuntime).Assembly
            .GetTypes()
            .Where(type => type != typeof(QuicConnectionRuntime))
            .Where(type => type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
                .Any(method =>
                    method.Name == nameof(QuicConnectionRuntime.Transition)
                    && method.GetParameters() is [{ ParameterType: Type parameterType }, ..]
                    && parameterType == typeof(QuicConnectionEvent)))
            .ToArray();

        Assert.Empty(otherTypesWithConnectionEventTransition);
    }
}
