using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0093")]
public sealed class REQ_QUIC_CRT_0093
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task HighDensityHostDoesNotStartPerConnectionRuntimeConsumers()
    {
        FieldInfo processingTaskField = typeof(QuicConnectionRuntime).GetField(
            "processingTask",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

        using QuicConnectionRuntimeHost host = new(2);
        List<QuicConnectionRuntime> runtimes = [];

        try
        {
            for (ulong index = 1; index <= 16; index++)
            {
                QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
                runtimes.Add(runtime);
                Assert.True(host.TryRegisterConnection(new QuicConnectionHandle(index), runtime));
                Assert.Null(processingTaskField.GetValue(runtime));
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
