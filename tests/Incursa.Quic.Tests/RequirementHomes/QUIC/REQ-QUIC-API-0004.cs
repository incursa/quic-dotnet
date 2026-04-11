using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0004">The QuicStream type MUST derive from Stream and expose the stream identifier, stream direction, read-side and write-side closed-completion tasks, the narrow abort control surface, and the standard capability members used by the currently supported consumer slice, including a truthful writable-side flag only on send-capable streams.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0004")]
public sealed class REQ_QUIC_API_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicStream_ExposesTheNarrowAbortAndCompletionSurface()
    {
        Assert.True(typeof(Stream).IsAssignableFrom(typeof(QuicStream)));

        string[] propertyNames = typeof(QuicStream)
            .GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Contains("Id", propertyNames);
        Assert.Contains("ReadsClosed", propertyNames);
        Assert.Contains("Type", propertyNames);
        Assert.Contains("WritesClosed", propertyNames);

        System.Reflection.MethodInfo? abortMethod = typeof(QuicStream).GetMethod(
            nameof(QuicStream.Abort),
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance,
            [typeof(QuicAbortDirection), typeof(long)]);

        Assert.NotNull(abortMethod);
        Assert.Equal(typeof(void), abortMethod!.ReturnType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackStreamEntry_ReturnsRealQuicStreamFacades()
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
        Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask);

        QuicConnection serverConnection = await acceptConnectionTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            Task<QuicStream> serverAcceptTask = serverConnection.AcceptInboundStreamAsync().AsTask();
            await Task.Yield();
            Task<QuicStream> clientOpenTask = clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask();

            Task completionTask = Task.WhenAll(serverAcceptTask, clientOpenTask);
            Task completedTask = await Task.WhenAny(completionTask, Task.Delay(TimeSpan.FromSeconds(5)));
            if (completedTask != completionTask)
            {
                throw new TimeoutException(
                    $"Stream entry did not complete. ServerAcceptCompleted={serverAcceptTask.IsCompleted}; ClientOpenCompleted={clientOpenTask.IsCompleted}; Server runtime: {QuicLoopbackEstablishmentTestSupport.DescribeConnection(serverConnection)}; Client runtime: {QuicLoopbackEstablishmentTestSupport.DescribeConnection(clientConnection)}");
            }

            await completionTask;

            QuicStream serverStream = await serverAcceptTask;
            QuicStream clientStream = await clientOpenTask;

            try
            {
                Assert.IsType<QuicStream>(clientStream);
                Assert.IsType<QuicStream>(serverStream);
                Assert.Equal(QuicStreamType.Bidirectional, clientStream.Type);
                Assert.Equal(QuicStreamType.Bidirectional, serverStream.Type);
                Assert.Equal(clientStream.Id, serverStream.Id);
                Assert.Equal(0, clientStream.Id);
                Assert.True(clientStream.CanRead);
                Assert.True(serverStream.CanRead);
                Assert.True(clientStream.CanWrite);
                Assert.True(serverStream.CanWrite);
                Assert.False(clientStream.ReadsClosed.IsCompleted);
                Assert.False(serverStream.ReadsClosed.IsCompleted);
                Assert.False(clientStream.WritesClosed.IsCompleted);
                Assert.False(serverStream.WritesClosed.IsCompleted);
            }
            finally
            {
                await serverStream.DisposeAsync();
                await clientStream.DisposeAsync();
            }
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }
}
