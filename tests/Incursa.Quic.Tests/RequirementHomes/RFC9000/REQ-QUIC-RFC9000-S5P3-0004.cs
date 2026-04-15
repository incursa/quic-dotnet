using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P3-0004">When implementing the server role, an application protocol MAY listen for incoming connections, which prepares for the exchange described in Section 7.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P3-0004")]
public sealed class REQ_QUIC_RFC9000_S5P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenAsync_OpensARealLoopbackListenerForTheServerRole()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            Assert.IsType<QuicConnection>(serverConnection);
            Assert.IsType<QuicConnection>(clientConnection);
            Assert.NotSame(serverConnection, clientConnection);
        }
        finally
        {
            await clientConnection.DisposeAsync();
            await serverConnection.DisposeAsync();
        }
    }
}
