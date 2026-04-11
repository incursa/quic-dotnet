using System.Net;
using System.Net.Security;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0002">The library now exposes the server-side listener entry surface through QuicListener.ListenAsync(QuicListenerOptions, CancellationToken) and QuicListener.AcceptConnectionAsync(CancellationToken), while keeping client connect deferred.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0002")]
public sealed class REQ_QUIC_API_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ListenAsync_RejectsNullOptions()
    {
        Assert.Throws<ArgumentNullException>(() => QuicListener.ListenAsync(null!));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ListenAsync_RejectsMissingListenEndPoint()
    {
        QuicListenerOptions options = CreateListenerOptions();
        options.ListenEndPoint = null!;

        Assert.Throws<ArgumentNullException>(() => QuicListener.ListenAsync(options));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ListenAsync_RejectsEmptyApplicationProtocols()
    {
        QuicListenerOptions options = CreateListenerOptions();
        options.ApplicationProtocols = [];

        Assert.Throws<ArgumentException>(() => QuicListener.ListenAsync(options));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ListenAsync_RejectsMissingConnectionOptionsCallback()
    {
        QuicListenerOptions options = CreateListenerOptions();
        options.ConnectionOptionsCallback = null!;

        Assert.Throws<ArgumentNullException>(() => QuicListener.ListenAsync(options));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ListenAsync_RejectsNegativeListenBacklog()
    {
        QuicListenerOptions options = CreateListenerOptions();
        options.ListenBacklog = -1;

        Assert.Throws<ArgumentOutOfRangeException>(() => QuicListener.ListenAsync(options));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenAsync_ReturnsARealListenerAndDisposesCleanly()
    {
        QuicListener listener = await QuicListener.ListenAsync(CreateListenerOptions());

        Assert.IsType<QuicListener>(listener);

        await listener.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() => listener.AcceptConnectionAsync());
    }

    private static QuicListenerOptions CreateListenerOptions(
        Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>>? connectionOptionsCallback = null)
    {
        return new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = connectionOptionsCallback ?? ((connection, clientHello, cancellationToken) => ValueTask.FromResult(new QuicServerConnectionOptions())),
        };
    }
}
