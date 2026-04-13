using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0013">The library MUST honor the mainstream BCL-shaped client TLS validation path on the existing SslClientAuthenticationOptions carrier, including TargetHost, CertificateChainPolicy, CertificateRevocationCheckMode, and RemoteCertificateValidationCallback, while keeping QuicPeerCertificatePolicy as the separate exact-pinning floor.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0013")]
public sealed class REQ_QUIC_API_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Capture_PreservesStandardValidationInputsIntoTheInternalOptions()
    {
        IPEndPoint remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        QuicClientConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            remoteEndPoint,
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);

        X509ChainPolicy originalChainPolicy = options.ClientAuthenticationOptions.CertificateChainPolicy!;
        Assert.Equal("localhost", options.ClientAuthenticationOptions.TargetHost);
        Assert.Null(options.ClientAuthenticationOptions.RemoteCertificateValidationCallback);

        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(options, nameof(options));

        options.ClientAuthenticationOptions.TargetHost = "mutated.example";
        originalChainPolicy.CustomTrustStore.Clear();

        Assert.Equal("localhost", settings.Options.ClientAuthenticationOptions.TargetHost);
        Assert.NotNull(settings.Options.ClientAuthenticationOptions.CertificateChainPolicy);
        Assert.NotSame(originalChainPolicy, settings.Options.ClientAuthenticationOptions.CertificateChainPolicy);
        Assert.Equal(X509ChainTrustMode.CustomRootTrust, settings.Options.ClientAuthenticationOptions.CertificateChainPolicy!.TrustMode);
        Assert.Equal(X509RevocationMode.NoCheck, settings.Options.ClientAuthenticationOptions.CertificateChainPolicy.RevocationMode);
        Assert.Single(settings.Options.ClientAuthenticationOptions.CertificateChainPolicy.CustomTrustStore);
        Assert.Null(settings.Options.ClientAuthenticationOptions.RemoteCertificateValidationCallback);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectAsync_AcceptsStandardValidationWithMatchingTargetHostAndTrustPolicy()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            Assert.NotNull(serverConnection);
            Assert.NotNull(clientConnection);
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
    public async Task ConnectAsync_FailsClosedWhenTrustedRootDoesNotMatch()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        using X509Certificate2 wrongTrustedCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "localhost",
            trustedServerCertificate: wrongTrustedCertificate);

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);

        QuicException exception = await Assert.ThrowsAsync<QuicException>(async () =>
            await QuicConnection.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal(QuicError.TransportError, exception.QuicError);
        Assert.Equal((long)QuicTransportErrorCode.ProtocolViolation, exception.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ConnectAsync_FailsClosedWhenTargetHostDoesNotMatch()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "example.com",
            trustedServerCertificate: serverCertificate);

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);

        QuicException exception = await Assert.ThrowsAsync<QuicException>(async () =>
            await QuicConnection.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal(QuicError.TransportError, exception.QuicError);
        Assert.Equal((long)QuicTransportErrorCode.ProtocolViolation, exception.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsMixedExactPinAndStandardValidationInputs()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, 443),
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);
        clientOptions.PeerCertificatePolicy = new QuicPeerCertificatePolicy
        {
            ExactPeerLeafCertificateDer = serverCertificate.RawData,
            ExplicitTrustMaterialSha256 = SHA256.HashData(serverCertificate.RawData),
        };

        Assert.Throws<NotSupportedException>(() => QuicConnection.ConnectAsync(clientOptions));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsPeerCertificatePolicyWithCallbackValidationInputs()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint());
        clientOptions.PeerCertificatePolicy = new QuicPeerCertificatePolicy
        {
            ExactPeerLeafCertificateDer = serverCertificate.RawData,
            ExplicitTrustMaterialSha256 = SHA256.HashData(serverCertificate.RawData),
        };

        Assert.Throws<NotSupportedException>(() => QuicConnection.ConnectAsync(clientOptions));
    }
}
