using System.Collections.Generic;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0010")]
public sealed class REQ_QUIC_CRT_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PathLifecycleTimerAndStreamStateFieldsDoNotUseConcurrentCollections()
    {
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.IsType<Dictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord>>(runtime.CandidatePaths);
        Assert.IsType<Dictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord>>(runtime.RecentlyValidatedPaths);
        Assert.IsType<Dictionary<ulong, byte[]>>(runtime.StatelessResetTokensByConnectionId);
        Assert.IsType<Dictionary<string, QuicConnectionRuntime.QuicConnectionNewTokenEmissionRecord>>(runtime.NewTokenEmissionsByRemoteAddress);
        Assert.Equal(0, runtime.BufferedEstablishmentHandshakePacketCount);
        Assert.IsType<QuicConnectionStreamRegistry>(runtime.StreamRegistry);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.IdleTimeoutState);
    }
}
