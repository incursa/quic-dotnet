using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P5P6-0001">Endpoints MAY prevent connection attempts or migration to a loopback address.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S21P5P6-0001")]
public sealed class REQ_QUIC_RFC9000_S21P5P6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectAsync_AllowsLoopbackConnectionAttemptsFromTheClientRole()
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

        QuicConnection clientConnection = await connectTask;
        QuicConnection serverConnection = await acceptTask;

        try
        {
            Assert.IsType<QuicConnection>(clientConnection);
            Assert.IsType<QuicConnection>(serverConnection);
            Assert.NotSame(clientConnection, serverConnection);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }
}
