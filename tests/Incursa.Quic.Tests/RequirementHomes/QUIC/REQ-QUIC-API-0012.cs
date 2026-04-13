using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-API-0012")]
public sealed class REQ_QUIC_API_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicClientConnectionOptions_ExposesPeerCertificatePolicyCarrier()
    {
        QuicClientConnectionOptions options = new();

        Assert.Null(options.PeerCertificatePolicy);

        options.PeerCertificatePolicy = new QuicPeerCertificatePolicy
        {
            ExactPeerLeafCertificateDer = new byte[] { 0x01, 0x02 },
            ExplicitTrustMaterialSha256 = new byte[32],
        };

        Assert.Equal([0x01, 0x02], options.PeerCertificatePolicy.ExactPeerLeafCertificateDer.ToArray());
        Assert.Equal(new byte[32], options.PeerCertificatePolicy.ExplicitTrustMaterialSha256.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Capture_PreservesPeerCertificatePolicyBytesIntoTheInternalSnapshot()
    {
        IPEndPoint remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        byte[] exactPeerLeafCertificateDer = [0x10, 0x20, 0x30, 0x40];
        byte[] explicitTrustMaterialSha256 = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();
        byte originalExactByte = exactPeerLeafCertificateDer[0];
        byte originalTrustByte = explicitTrustMaterialSha256[0];

        QuicClientConnectionOptions options = CreatePeerPolicyClientOptions(
            remoteEndPoint,
            exactPeerLeafCertificateDer,
            explicitTrustMaterialSha256);

        exactPeerLeafCertificateDer[0] ^= 0x80;
        explicitTrustMaterialSha256[0] ^= 0x80;

        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(options, nameof(options));

        Assert.NotNull(settings.ClientCertificatePolicySnapshot);
        Assert.Equal(originalExactByte, settings.ClientCertificatePolicySnapshot!.ExactPeerLeafCertificateDer.Span[0]);
        Assert.Equal(originalTrustByte, settings.ClientCertificatePolicySnapshot.ExplicitTrustMaterialSha256.Span[0]);
        Assert.Equal(
            settings.ClientCertificatePolicySnapshot.ExactPeerLeafCertificateDer.ToArray(),
            settings.Options.PeerCertificatePolicy!.ExactPeerLeafCertificateDer.ToArray());
        Assert.Equal(
            settings.ClientCertificatePolicySnapshot.ExplicitTrustMaterialSha256.ToArray(),
            settings.Options.PeerCertificatePolicy.ExplicitTrustMaterialSha256.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectAsync_AcceptsAMatchingPeerCertificatePolicyOnTheSupportedLoopbackPath()
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

        QuicClientConnectionOptions clientOptions = CreatePeerPolicyClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            serverCertificate.RawData,
            SHA256.HashData(serverCertificate.RawData));

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
    public async Task ConnectAsync_FailsClosedWhenExactPeerIdentityIsMissing()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();

        await AssertPeerCertificatePolicyFailureAsync(
            serverCertificate,
            new QuicPeerCertificatePolicy
            {
                ExactPeerLeafCertificateDer = ReadOnlyMemory<byte>.Empty,
                ExplicitTrustMaterialSha256 = SHA256.HashData(serverCertificate.RawData),
            });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ConnectAsync_FailsClosedWhenExplicitTrustMaterialIsMissing()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();

        await AssertPeerCertificatePolicyFailureAsync(
            serverCertificate,
            new QuicPeerCertificatePolicy
            {
                ExactPeerLeafCertificateDer = serverCertificate.RawData,
                ExplicitTrustMaterialSha256 = ReadOnlyMemory<byte>.Empty,
            });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ConnectAsync_FailsClosedWhenExactPeerIdentityDoesNotMatch()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();

        await AssertPeerCertificatePolicyFailureAsync(
            serverCertificate,
            new QuicPeerCertificatePolicy
            {
                ExactPeerLeafCertificateDer = MutateFirstByte(serverCertificate.RawData),
                ExplicitTrustMaterialSha256 = SHA256.HashData(serverCertificate.RawData),
            });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ConnectAsync_FailsClosedWhenExplicitTrustMaterialDoesNotMatch()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();

        await AssertPeerCertificatePolicyFailureAsync(
            serverCertificate,
            new QuicPeerCertificatePolicy
            {
                ExactPeerLeafCertificateDer = serverCertificate.RawData,
                ExplicitTrustMaterialSha256 = MutateFirstByte(SHA256.HashData(serverCertificate.RawData)),
            });
    }

    private static async Task AssertPeerCertificatePolicyFailureAsync(
        X509Certificate2 serverCertificate,
        QuicPeerCertificatePolicy peerCertificatePolicy)
    {
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        QuicClientConnectionOptions clientOptions = CreatePeerPolicyClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            peerCertificatePolicy);
        clientOptions.ClientAuthenticationOptions.RemoteCertificateValidationCallback = static (_, _, _, _) => true;

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);

        QuicException exception = await Assert.ThrowsAsync<QuicException>(async () =>
            await QuicConnection.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal(QuicError.TransportError, exception.QuicError);
        Assert.Equal((long)QuicTransportErrorCode.ProtocolViolation, exception.TransportErrorCode);
    }

    private static QuicClientConnectionOptions CreatePeerPolicyClientOptions(
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> exactPeerLeafCertificateDer,
        ReadOnlyMemory<byte> explicitTrustMaterialSha256)
    {
        return CreatePeerPolicyClientOptions(
            remoteEndPoint,
            new QuicPeerCertificatePolicy
            {
                ExactPeerLeafCertificateDer = exactPeerLeafCertificateDer,
                ExplicitTrustMaterialSha256 = explicitTrustMaterialSha256,
            });
    }

    private static QuicClientConnectionOptions CreatePeerPolicyClientOptions(
        IPEndPoint remoteEndPoint,
        QuicPeerCertificatePolicy peerCertificatePolicy)
    {
        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = remoteEndPoint,
            PeerCertificatePolicy = peerCertificatePolicy,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            },
        };
    }

    private static byte[] MutateFirstByte(ReadOnlySpan<byte> source)
    {
        byte[] mutated = source.ToArray();
        mutated[0] ^= 0x80;
        return mutated;
    }
}
