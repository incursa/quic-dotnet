using System.Net;
using System.Net.Security;
using System.Security.Authentication;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0008">Pending accept operations honor cancellation, and listener disposal unblocks pending accepts with a terminal ObjectDisposedException outcome instead of pretending handshake completion.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0008")]
public sealed class REQ_QUIC_API_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AcceptConnectionAsync_HonorsCancellationWhilePending()
    {
        await using QuicListener listener = await QuicListener.ListenAsync(CreateListenerOptions());
        using CancellationTokenSource cancellationSource = new();

        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();

        await Task.Yield();
        cancellationSource.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => acceptTask);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DisposeAsync_UnblocksPendingAcceptWithObjectDisposedException()
    {
        QuicListener listener = await QuicListener.ListenAsync(CreateListenerOptions());
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();

        await Task.Yield();
        await listener.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => acceptTask);
    }

    private static QuicListenerOptions CreateListenerOptions()
    {
        return new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions()),
        };
    }
}
