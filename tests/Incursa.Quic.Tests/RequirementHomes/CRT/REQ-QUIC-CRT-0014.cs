using System.Collections.Generic;
using System.Collections.Concurrent;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0014")]
public sealed class REQ_QUIC_CRT_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointSharedRouteAndTokenRegistriesUseConcurrentDictionaries()
    {
        QuicConnectionRuntimeEndpoint endpoint = new(1);

        Assert.True(IsConcurrentDictionary(endpoint.RouteIdsByHandle.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.RoutesByLength.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.StatelessResetConnectionIdsByRouteIdByHandle.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.StatelessResetTokenIdsByHandle.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.StatelessResetBindingsByMatchKey.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.StatelessResetBindingsByConnectionId.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.RetainedStatelessResetBindingsByRouteLength.GetType()));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointSharedRouteAndTokenRegistriesDoNotMoveIntoConnectionRuntime()
    {
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntimeEndpoint endpoint = new(1);

        Assert.IsType<Dictionary<ulong, byte[]>>(runtime.StatelessResetTokensByConnectionId);
        Assert.IsType<Dictionary<string, QuicConnectionRuntime.QuicConnectionNewTokenEmissionRecord>>(runtime.NewTokenEmissionsByRemoteAddress);

        Assert.True(IsConcurrentDictionary(endpoint.RouteIdsByHandle.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.RoutesByLength.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.StatelessResetConnectionIdsByRouteIdByHandle.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.StatelessResetTokenIdsByHandle.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.StatelessResetBindingsByMatchKey.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.StatelessResetBindingsByConnectionId.GetType()));
        Assert.True(IsConcurrentDictionary(endpoint.RetainedStatelessResetBindingsByRouteLength.GetType()));
    }

    private static bool IsConcurrentDictionary(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ConcurrentDictionary<,>);
    }
}
