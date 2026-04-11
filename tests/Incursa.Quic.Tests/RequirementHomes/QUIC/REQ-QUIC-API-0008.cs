using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0008">Pending accept and connect operations honor cancellation, and listener or client-host disposal unblocks pending work with terminal outcomes instead of pretending handshake completion.</workbench-requirement>
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

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectAsync_HonorsCancellationWhilePending()
    {
        using CancellationTokenSource cancellationSource = new();

        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            CreateClientOptions(GetUnusedLoopbackEndPoint()),
            cancellationSource.Token).AsTask();

        await Task.Yield();
        cancellationSource.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connectTask);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientHostDisposeAsync_UnblocksPendingConnectWithObjectDisposedException()
    {
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            CreateClientOptions(GetUnusedLoopbackEndPoint()),
            "options");
        await using QuicClientConnectionHost host = new(settings);

        Task<QuicConnection> connectTask = host.ConnectAsync().AsTask();

        await Task.Yield();
        await host.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => connectTask);
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

    private static QuicClientConnectionOptions CreateClientOptions(IPEndPoint remoteEndPoint)
    {
        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = remoteEndPoint,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                RemoteCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.RemoteCertificateChainErrors,
            },
        };
    }

    private static IPEndPoint GetUnusedLoopbackEndPoint()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (IPEndPoint)socket.LocalEndPoint!;
    }
}
