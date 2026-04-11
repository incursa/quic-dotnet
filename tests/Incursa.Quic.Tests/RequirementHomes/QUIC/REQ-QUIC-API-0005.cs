using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0005">The listener and client surfaces carry configuration through QuicListenerOptions, QuicClientConnectionOptions, and QuicServerConnectionOptions, and the supported client TLS subset is explicit, callback-gated, and reject-first rather than implied.</workbench-requirement>
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
    public void QuicClientConnectionOptions_ExposeOnlyTheApprovedClientKnobs()
    {
        string[] propertyNames = typeof(QuicClientConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "ClientAuthenticationOptions",
            "LocalEndPoint",
            "RemoteEndPoint",
        }, propertyNames);

        QuicClientConnectionOptions options = new();
        Assert.Null(options.LocalEndPoint);
        Assert.Null(options.ClientAuthenticationOptions);
        Assert.Null(options.RemoteEndPoint);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsUnsupportedClientTlsSettingsDeterministically()
    {
        QuicClientConnectionOptions targetHostOptions = CreateClientOptions();
        targetHostOptions.ClientAuthenticationOptions.TargetHost = "example.com";
        Assert.Throws<NotSupportedException>(() => QuicConnection.ConnectAsync(targetHostOptions));

        QuicClientConnectionOptions emptyAlpnOptions = CreateClientOptions();
        emptyAlpnOptions.ClientAuthenticationOptions.ApplicationProtocols = [];
        Assert.Throws<ArgumentException>(() => QuicConnection.ConnectAsync(emptyAlpnOptions));

        QuicClientConnectionOptions missingCallbackOptions = CreateClientOptions();
        missingCallbackOptions.ClientAuthenticationOptions.RemoteCertificateValidationCallback = null;
        Assert.Throws<NotSupportedException>(() => QuicConnection.ConnectAsync(missingCallbackOptions));

        QuicClientConnectionOptions protocolOptions = CreateClientOptions();
        protocolOptions.ClientAuthenticationOptions.EnabledSslProtocols = SslProtocols.Tls12;
        Assert.Throws<NotSupportedException>(() => QuicConnection.ConnectAsync(protocolOptions));
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

    private static QuicClientConnectionOptions CreateClientOptions()
    {
        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 443),
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                RemoteCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.RemoteCertificateChainErrors,
            },
        };
    }
}
