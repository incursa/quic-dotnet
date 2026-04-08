namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0006")]
public sealed class REQ_QUIC_CRT_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HostRoutesTheSameHandleToTheSameShardEveryTime()
    {
        using QuicConnectionRuntimeHost host = new(5);
        QuicConnectionHandle handle = new(1234);

        int firstShard = host.GetShardIndex(handle);
        int secondShard = host.GetShardIndex(handle);
        int thirdShard = host.GetShardIndex(handle);

        Assert.Equal(firstShard, secondShard);
        Assert.Equal(secondShard, thirdShard);
        Assert.InRange(firstShard, 0, host.ShardCount - 1);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void HostRejectsNonPositiveShardCounts()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicConnectionRuntimeHost(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicConnectionRuntimeHost(-1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void HostRejectsDuplicateHandleOwnership()
    {
        using QuicConnectionRuntimeHost host = new(2);
        QuicConnectionHandle handle = new(9001);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.True(host.TryRegisterConnection(handle, firstRuntime));
        Assert.False(host.TryRegisterConnection(handle, secondRuntime));
        Assert.True(host.TryUnregisterConnection(handle));
    }
}
