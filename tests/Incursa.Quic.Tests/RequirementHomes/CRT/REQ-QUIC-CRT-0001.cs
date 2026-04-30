namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0001")]
public sealed class REQ_QUIC_CRT_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RuntimeRejectsASecondDedicatedOwnerConsumer()
    {
        using CancellationTokenSource cancellation = new();
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        Task consumer = runtime.RunAsync(cancellationToken: cancellation.Token);

        Assert.Throws<InvalidOperationException>(() =>
        {
            _ = runtime.RunAsync();
        });

        cancellation.Cancel();
        await consumer;
        await runtime.DisposeAsync();
    }
}
