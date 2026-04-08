namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0094")]
public sealed class REQ_QUIC_CRT_0094
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HostShardCountIsConfiguredIndependentlyOfConnectionCount()
    {
        using QuicConnectionRuntimeHost host = new(3);

        Assert.Equal(3, host.ShardCount);

        for (ulong index = 1; index <= 64; index++)
        {
            QuicConnectionHandle handle = new(index);
            QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

            Assert.True(host.TryRegisterConnection(handle, runtime));
            Assert.InRange(host.GetShardIndex(handle), 0, host.ShardCount - 1);
            Assert.True(host.TryUnregisterConnection(handle));
            await runtime.DisposeAsync();
        }

        Assert.Equal(3, host.ShardCount);
    }
}
