using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using IncursaClientConnection = global::Incursa.Quic.QuicConnection;
using IncursaClientConnectionOptions = global::Incursa.Quic.QuicClientConnectionOptions;
using IncursaListener = global::Incursa.Quic.QuicListener;
using IncursaListenerOptions = global::Incursa.Quic.QuicListenerOptions;
using IncursaServerConnectionOptions = global::Incursa.Quic.QuicServerConnectionOptions;
using SystemNetClientConnection = global::System.Net.Quic.QuicConnection;
using SystemNetClientConnectionOptions = global::System.Net.Quic.QuicClientConnectionOptions;
using SystemNetListener = global::System.Net.Quic.QuicListener;
using SystemNetListenerOptions = global::System.Net.Quic.QuicListenerOptions;
using SystemNetServerConnectionOptions = global::System.Net.Quic.QuicServerConnectionOptions;

namespace Incursa.Quic.Benchmarks;

public enum QuicPublicApiLoopbackImplementation
{
    IncursaQuic,
    SystemNetQuic,
}

/// <summary>
/// Benchmarks matched public-facade loopback connection establishment against Incursa.Quic and System.Net.Quic.
/// </summary>
[MemoryDiagnoser]
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public class QuicPublicApiLoopbackBenchmarks
{
    private X509Certificate2? serverCertificate;

    [ParamsSource(nameof(GetSupportedImplementations))]
    public QuicPublicApiLoopbackImplementation Implementation { get; set; }

    public IEnumerable<QuicPublicApiLoopbackImplementation> GetSupportedImplementations()
    {
        if (IncursaClientConnection.IsSupported && IncursaListener.IsSupported)
        {
            yield return QuicPublicApiLoopbackImplementation.IncursaQuic;
        }
        else
        {
            Console.WriteLine(
                $"Skipping Incursa.Quic public loopback benchmarks because support markers are not both true. QuicConnection.IsSupported={IncursaClientConnection.IsSupported}, QuicListener.IsSupported={IncursaListener.IsSupported}.");
        }

        if (SystemNetClientConnection.IsSupported && SystemNetListener.IsSupported)
        {
            yield return QuicPublicApiLoopbackImplementation.SystemNetQuic;
        }
        else
        {
            Console.WriteLine(
                $"Skipping System.Net.Quic public loopback benchmarks because support markers are not both true. QuicConnection.IsSupported={SystemNetClientConnection.IsSupported}, QuicListener.IsSupported={SystemNetListener.IsSupported}.");
        }
    }

    [GlobalSetup]
    public void GlobalSetup()
    {
        serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        serverCertificate?.Dispose();
        serverCertificate = null;
    }

    [Benchmark]
    public Task LoopbackConnectAcceptDispose()
    {
        X509Certificate2 certificate = serverCertificate ?? throw new InvalidOperationException("The benchmark certificate has not been initialized.");
        return Implementation switch
        {
            QuicPublicApiLoopbackImplementation.IncursaQuic => RunIncursaConnectAcceptDisposeAsync(certificate),
            QuicPublicApiLoopbackImplementation.SystemNetQuic => RunSystemNetConnectAcceptDisposeAsync(certificate),
            _ => throw new ArgumentOutOfRangeException(nameof(Implementation)),
        };
    }

    private static async Task RunIncursaConnectAcceptDisposeAsync(X509Certificate2 serverCertificate)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(10));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(listenEndPoint, serverCertificate),
            cancellationSource.Token).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                serverCertificate),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);

        await using IncursaClientConnection serverConnection = await acceptTask.ConfigureAwait(false);
        await using IncursaClientConnection clientConnection = await connectTask.ConfigureAwait(false);
    }

    private static async Task RunSystemNetConnectAcceptDisposeAsync(X509Certificate2 serverCertificate)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(10));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(listenEndPoint, serverCertificate),
            cancellationSource.Token).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                serverCertificate),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);

        await using SystemNetClientConnection serverConnection = await acceptTask.ConfigureAwait(false);
        await using SystemNetClientConnection clientConnection = await connectTask.ConfigureAwait(false);
    }
}

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal static class QuicPublicApiLoopbackBenchmarkSupport
{
    private const string LoopbackHostName = "localhost";

    internal static X509Certificate2 CreateServerCertificate()
    {
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            $"CN={LoopbackHostName}",
            leafKey,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        SubjectAlternativeNameBuilder subjectAlternativeName = new();
        subjectAlternativeName.AddDnsName(LoopbackHostName);
        request.CertificateExtensions.Add(subjectAlternativeName.Build());

        using X509Certificate2 ephemeralCertificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(7));

        byte[] pkcs12 = ephemeralCertificate.Export(X509ContentType.Pkcs12);
        return X509CertificateLoader.LoadPkcs12(
            pkcs12,
            (string?)null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
    }

    internal static IPEndPoint GetUnusedLoopbackEndPoint()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (IPEndPoint)socket.LocalEndPoint!;
    }

    internal static IncursaListenerOptions CreateIncursaListenerOptions(IPEndPoint listenEndPoint, X509Certificate2 serverCertificate)
    {
        return new IncursaListenerOptions
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateIncursaServerOptions(serverCertificate)),
        };
    }

    internal static SystemNetListenerOptions CreateSystemNetListenerOptions(IPEndPoint listenEndPoint, X509Certificate2 serverCertificate)
    {
        return new SystemNetListenerOptions
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateSystemNetServerOptions(serverCertificate)),
        };
    }

    internal static IncursaClientConnectionOptions CreateIncursaClientOptions(IPEndPoint remoteEndPoint, X509Certificate2 serverCertificate)
    {
        return new IncursaClientConnectionOptions
        {
            DefaultCloseErrorCode = 0,
            DefaultStreamErrorCode = 0,
            RemoteEndPoint = remoteEndPoint,
            ClientAuthenticationOptions = CreateClientAuthenticationOptions(serverCertificate),
        };
    }

    internal static SystemNetClientConnectionOptions CreateSystemNetClientOptions(IPEndPoint remoteEndPoint, X509Certificate2 serverCertificate)
    {
        return new SystemNetClientConnectionOptions
        {
            DefaultCloseErrorCode = 0,
            DefaultStreamErrorCode = 0,
            RemoteEndPoint = remoteEndPoint,
            ClientAuthenticationOptions = CreateClientAuthenticationOptions(serverCertificate),
        };
    }

    private static IncursaServerConnectionOptions CreateIncursaServerOptions(X509Certificate2 serverCertificate)
    {
        return new IncursaServerConnectionOptions
        {
            DefaultCloseErrorCode = 0,
            DefaultStreamErrorCode = 0,
            ServerAuthenticationOptions = CreateServerAuthenticationOptions(serverCertificate),
        };
    }

    private static SystemNetServerConnectionOptions CreateSystemNetServerOptions(X509Certificate2 serverCertificate)
    {
        return new SystemNetServerConnectionOptions
        {
            DefaultCloseErrorCode = 0,
            DefaultStreamErrorCode = 0,
            ServerAuthenticationOptions = CreateServerAuthenticationOptions(serverCertificate),
        };
    }

    private static SslServerAuthenticationOptions CreateServerAuthenticationOptions(X509Certificate2 serverCertificate)
    {
        return new SslServerAuthenticationOptions
        {
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ServerCertificate = serverCertificate,
            EnabledSslProtocols = SslProtocols.Tls13,
            EncryptionPolicy = EncryptionPolicy.RequireEncryption,
        };
    }

    private static SslClientAuthenticationOptions CreateClientAuthenticationOptions(X509Certificate2 serverCertificate)
    {
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);

        return new SslClientAuthenticationOptions
        {
            AllowRenegotiation = false,
            AllowTlsResume = true,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            EnabledSslProtocols = SslProtocols.Tls13,
            EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            TargetHost = LoopbackHostName,
            CertificateChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck,
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                CustomTrustStore = { trustAnchor },
            },
        };
    }
}
