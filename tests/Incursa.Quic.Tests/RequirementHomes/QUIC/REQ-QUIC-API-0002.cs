using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0002">The library now exposes the server-side listener entry surface through QuicListener.ListenAsync(QuicListenerOptions, CancellationToken) and QuicListener.AcceptConnectionAsync(CancellationToken), and it exposes the first honest client entry surface through QuicConnection.ConnectAsync(QuicClientConnectionOptions, CancellationToken).</workbench-requirement>
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
    public async Task ConnectAsync_And_AcceptConnectionAsync_CompleteARealLoopbackEstablishment()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> callbackRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
        QuicConnection? observedConnection = null;
        string? observedServerName = null;
        SslProtocols observedProtocols = default;

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = async (connection, clientHello, cancellationToken) =>
            {
                observedConnection = connection;
                observedServerName = clientHello.ServerName;
                observedProtocols = clientHello.SslProtocols;
                callbackEntered.TrySetResult(true);
                await callbackRelease.Task.WaitAsync(cancellationToken);
                return QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
            },
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

        await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(connectTask.IsCompleted);
        Assert.False(acceptTask.IsCompleted);

        callbackRelease.TrySetResult(true);

        Task completionTask = Task.WhenAll(connectTask, acceptTask);
        Task completedTask = await Task.WhenAny(completionTask, Task.Delay(TimeSpan.FromSeconds(5)));
        if (completedTask != completionTask)
        {
            string listenerHostTaskDescription = DescribeListenerHostTask(listener);
            string listenerTransitionDescription = DescribeFirstPendingConnectionTransition(listener);
            throw new TimeoutException(
                $"Loopback establishment did not complete. Server runtime: {QuicLoopbackEstablishmentTestSupport.DescribeConnection(observedConnection)}; {listenerHostTaskDescription}; {listenerTransitionDescription}");
        }

        await completionTask;

        QuicConnection clientConnection = await connectTask;
        QuicConnection serverConnection = await acceptTask;

        try
        {
            Assert.IsType<QuicConnection>(clientConnection);
            Assert.IsType<QuicConnection>(serverConnection);
            Assert.NotSame(clientConnection, serverConnection);
            Assert.Same(serverConnection, observedConnection);
            Assert.True(string.IsNullOrEmpty(observedServerName));
            Assert.Equal(SslProtocols.Tls13, observedProtocols);
            Assert.NotNull(GetRuntime(clientConnection).TlsState.PeerTransportParameters);
            Assert.NotNull(GetRuntime(serverConnection).TlsState.PeerTransportParameters);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsNullOptions()
    {
        Assert.Throws<ArgumentNullException>(() => QuicConnection.ConnectAsync(null!));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsMissingRemoteEndPoint()
    {
        QuicClientConnectionOptions options = CreateClientOptions();
        options.RemoteEndPoint = null!;

        Assert.Throws<ArgumentNullException>(() => QuicConnection.ConnectAsync(options));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsMissingClientAuthenticationOptions()
    {
        QuicClientConnectionOptions options = CreateClientOptions();
        options.ClientAuthenticationOptions = null!;

        Assert.Throws<ArgumentNullException>(() => QuicConnection.ConnectAsync(options));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsUnsupportedRemoteEndPointTypes()
    {
        QuicClientConnectionOptions options = CreateClientOptions();
        options.RemoteEndPoint = new DnsEndPoint("localhost", 443);

        Assert.Throws<NotSupportedException>(() => QuicConnection.ConnectAsync(options));
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

    private static QuicClientConnectionOptions CreateClientOptions()
    {
        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 443),
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

    private static string DescribeListenerHostTask(QuicListener listener)
    {
        FieldInfo? hostField = typeof(QuicListener).GetField("host", BindingFlags.Instance | BindingFlags.NonPublic);
        if (hostField?.GetValue(listener) is not QuicListenerHost listenerHost)
        {
            return "ListenerHost=<unavailable>";
        }

        FieldInfo? runningTaskField = typeof(QuicListenerHost).GetField("runningTask", BindingFlags.Instance | BindingFlags.NonPublic);
        if (runningTaskField?.GetValue(listenerHost) is not Task runningTask)
        {
            return "ListenerTask=<unavailable>";
        }

        string exceptionDescription = runningTask.Exception?.GetBaseException() is Exception exception
            ? $"{exception.GetType().Name}: {exception.Message}"
            : "<none>";
        return $"ListenerTaskStatus={runningTask.Status}; Faulted={runningTask.IsFaulted}; Canceled={runningTask.IsCanceled}; Exception={exceptionDescription}";
    }

    private static string DescribeFirstPendingConnectionTransition(QuicListener listener)
    {
        FieldInfo? hostField = typeof(QuicListener).GetField("host", BindingFlags.Instance | BindingFlags.NonPublic);
        if (hostField?.GetValue(listener) is not QuicListenerHost listenerHost)
        {
            return "ListenerTransitions=<host unavailable>";
        }

        FieldInfo? connectionsField = typeof(QuicListenerHost).GetField("connections", BindingFlags.Instance | BindingFlags.NonPublic);
        if (connectionsField?.GetValue(listenerHost) is not System.Collections.IEnumerable connections)
        {
            return "ListenerTransitions=<connections unavailable>";
        }

        foreach (object? entry in connections)
        {
            if (entry is null)
            {
                continue;
            }

            PropertyInfo? valueProperty = entry.GetType().GetProperty("Value", BindingFlags.Public | BindingFlags.Instance);
            object? pendingState = valueProperty?.GetValue(entry);
            if (pendingState is null)
            {
                continue;
            }

            PropertyInfo? historyProperty = pendingState.GetType().GetProperty("TransitionHistory", BindingFlags.Public | BindingFlags.Instance);
            if (historyProperty?.GetValue(pendingState) is not System.Collections.IEnumerable transitionHistory)
            {
                return "ListenerTransitions=<history unavailable>";
            }

            foreach (object? transitionObject in transitionHistory)
            {
                if (transitionObject is not QuicConnectionTransitionResult transition
                    || transition.EventKind != QuicConnectionEventKind.PacketReceived)
                {
                    continue;
                }

                string effectSummary = string.Join(
                    ", ",
                    transition.Effects.Select(effect => effect switch
                    {
                        QuicConnectionEmitDiagnosticEffect diagnosticEffect
                            => $"diag:{diagnosticEffect.Diagnostic.Name}",
                        QuicConnectionSendDatagramEffect
                            => $"send:{DescribePacketNumberSpace(effect)}",
                        _ => effect.GetType().Name,
                    }));

                return $"ListenerPacketTransition=Prev:{transition.PreviousPhase}; Curr:{transition.CurrentPhase}; StateChanged:{transition.StateChanged}; Effects:[{effectSummary}]";
            }

            return "ListenerTransitions=<no packet transition observed>";
        }

        return "ListenerTransitions=<no pending connection>";
    }

    private static string DescribePacketNumberSpace(QuicConnectionEffect effect)
    {
        if (effect is not QuicConnectionSendDatagramEffect sendEffect)
        {
            return effect.GetType().Name;
        }

        if (QuicPacketParser.TryGetPacketNumberSpace(sendEffect.Datagram.Span, out QuicPacketNumberSpace packetNumberSpace))
        {
            return packetNumberSpace.ToString();
        }

        return "Unclassified";
    }

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        FieldInfo? runtimeField = typeof(QuicConnection).GetField("runtime", BindingFlags.Instance | BindingFlags.NonPublic);
        return Assert.IsType<QuicConnectionRuntime>(runtimeField?.GetValue(connection));
    }
}
