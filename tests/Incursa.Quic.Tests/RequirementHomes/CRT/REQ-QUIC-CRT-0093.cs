namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0093")]
public sealed class REQ_QUIC_CRT_0093
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task HighDensityHostDoesNotStartPerConnectionRuntimeConsumers()
    {
        using QuicConnectionRuntimeHost host = new(2);
        List<QuicConnectionRuntime> runtimes = [];

        try
        {
            for (ulong index = 1; index <= 16; index++)
            {
                QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
                runtimes.Add(runtime);
                Assert.True(host.TryRegisterConnection(new QuicConnectionHandle(index), runtime));
                Assert.False(runtime.HasProcessingTask);
            }
        }
        finally
        {
            foreach (QuicConnectionRuntime runtime in runtimes)
            {
                await runtime.DisposeAsync();
            }
        }
    }
}
