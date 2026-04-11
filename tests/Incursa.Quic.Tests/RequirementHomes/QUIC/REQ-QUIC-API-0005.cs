using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0005">The listener surface carries configuration through QuicListenerOptions and QuicServerConnectionOptions, and the listener connection-options callback remains a narrow server-side selector rather than a middleware pipeline.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0005")]
public sealed class REQ_QUIC_API_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicListenerOptions_ExposeOnlyTheApprovedKnobs()
    {
        string[] propertyNames = typeof(QuicListenerOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "ApplicationProtocols",
            "ConnectionOptionsCallback",
            "ListenBacklog",
            "ListenEndPoint",
        }, propertyNames);

        PropertyInfo? callbackProperty = typeof(QuicListenerOptions).GetProperty(nameof(QuicListenerOptions.ConnectionOptionsCallback));
        Assert.NotNull(callbackProperty);
        Assert.Equal(typeof(Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>>), callbackProperty.PropertyType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicServerConnectionOptions_ExposeOnlyTheApprovedServerKnobs()
    {
        QuicServerConnectionOptions options = new();

        Assert.Equal(100, options.MaxInboundBidirectionalStreams);
        Assert.Equal(10, options.MaxInboundUnidirectionalStreams);

        string[] propertyNames = typeof(QuicServerConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "ServerAuthenticationOptions",
        }, propertyNames);

        PropertyInfo? authProperty = typeof(QuicServerConnectionOptions).GetProperty(nameof(QuicServerConnectionOptions.ServerAuthenticationOptions));
        Assert.NotNull(authProperty);
        Assert.Equal(typeof(SslServerAuthenticationOptions), authProperty.PropertyType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectionOptionsCallback_IsInvokedThroughTheNarrowListenerPath()
    {
        int invocationCount = 0;
        QuicConnection? observedConnection = null;
        string? observedServerName = null;
        SslProtocols observedProtocols = default;
        CancellationToken observedToken = default;

        QuicListenerOptions options = CreateListenerOptions((connection, clientHello, cancellationToken) =>
        {
            invocationCount++;
            observedConnection = connection;
            observedServerName = clientHello.ServerName;
            observedProtocols = clientHello.SslProtocols;
            observedToken = cancellationToken;
            return ValueTask.FromResult(new QuicServerConnectionOptions());
        });

        QuicListener listener = await QuicListener.ListenAsync(options);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();

        await Task.Yield();

        QuicConnection enqueuedConnection = await listener.EnqueueIncomingConnectionAsync(new SslClientHelloInfo("example.com", SslProtocols.Tls13));
        QuicConnection acceptedConnection = await acceptTask;

        Assert.Same(enqueuedConnection, acceptedConnection);
        Assert.Same(enqueuedConnection, observedConnection);
        Assert.Equal("example.com", observedServerName);
        Assert.Equal(SslProtocols.Tls13, observedProtocols);
        Assert.False(observedToken.IsCancellationRequested);
        Assert.Equal(1, invocationCount);

        await acceptedConnection.DisposeAsync();
        await listener.DisposeAsync();
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
