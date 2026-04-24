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
using IncursaStream = global::Incursa.Quic.QuicStream;
using IncursaStreamType = global::Incursa.Quic.QuicStreamType;
using SystemNetClientConnection = global::System.Net.Quic.QuicConnection;
using SystemNetClientConnectionOptions = global::System.Net.Quic.QuicClientConnectionOptions;
using SystemNetListener = global::System.Net.Quic.QuicListener;
using SystemNetListenerOptions = global::System.Net.Quic.QuicListenerOptions;
using SystemNetStream = global::System.Net.Quic.QuicStream;
using SystemNetStreamType = global::System.Net.Quic.QuicStreamType;

namespace Incursa.Quic.Benchmarks;

public enum QuicPublicApiStreamTransferImplementation
{
    IncursaQuic,
    SystemNetQuic,
}

/// <summary>
/// Benchmarks matched public-facade loopback request/response stream transfer against Incursa.Quic and System.Net.Quic.
/// </summary>
[MemoryDiagnoser]
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public class QuicPublicApiStreamTransferBenchmarks
{
    private const int PayloadBytes = 1024;

    private X509Certificate2? serverCertificate;
    private byte[]? requestPayload;
    private byte[]? responsePayload;

    [ParamsSource(nameof(GetSupportedImplementations))]
    public QuicPublicApiStreamTransferImplementation Implementation { get; set; }

    public IEnumerable<QuicPublicApiStreamTransferImplementation> GetSupportedImplementations()
    {
        if (IncursaClientConnection.IsSupported && IncursaListener.IsSupported)
        {
            yield return QuicPublicApiStreamTransferImplementation.IncursaQuic;
        }
        else
        {
            Console.WriteLine(
                $"Skipping Incursa.Quic public stream-transfer benchmarks because support markers are not both true. QuicConnection.IsSupported={IncursaClientConnection.IsSupported}, QuicListener.IsSupported={IncursaListener.IsSupported}.");
        }

        if (SystemNetClientConnection.IsSupported && SystemNetListener.IsSupported)
        {
            yield return QuicPublicApiStreamTransferImplementation.SystemNetQuic;
        }
        else
        {
            Console.WriteLine(
                $"Skipping System.Net.Quic public stream-transfer benchmarks because support markers are not both true. QuicConnection.IsSupported={SystemNetClientConnection.IsSupported}, QuicListener.IsSupported={SystemNetListener.IsSupported}.");
        }
    }

    [GlobalSetup]
    public void GlobalSetup()
    {
        serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        requestPayload = CreatePayload(PayloadBytes, 0x11);
        responsePayload = CreatePayload(PayloadBytes, 0x33);
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        serverCertificate?.Dispose();
        serverCertificate = null;
        requestPayload = null;
        responsePayload = null;
    }

    [Benchmark]
    public Task LoopbackRequestResponseDispose()
    {
        X509Certificate2 certificate = serverCertificate ?? throw new InvalidOperationException("The benchmark certificate has not been initialized.");
        byte[] request = requestPayload ?? throw new InvalidOperationException("The benchmark request payload has not been initialized.");
        byte[] response = responsePayload ?? throw new InvalidOperationException("The benchmark response payload has not been initialized.");

        return Implementation switch
        {
            QuicPublicApiStreamTransferImplementation.IncursaQuic => RunIncursaRequestResponseDisposeAsync(certificate, request, response),
            QuicPublicApiStreamTransferImplementation.SystemNetQuic => RunSystemNetRequestResponseDisposeAsync(certificate, request, response),
            _ => throw new ArgumentOutOfRangeException(nameof(Implementation)),
        };
    }

    private static async Task RunIncursaRequestResponseDisposeAsync(
        X509Certificate2 serverCertificate,
        byte[] requestPayload,
        byte[] responsePayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(listenEndPoint, serverCertificate),
            cancellationSource.Token).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                serverCertificate),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using IncursaClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using IncursaClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        Task<IncursaStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationSource.Token).AsTask();
        await Task.Yield();
        Task<IncursaStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            IncursaStreamType.Bidirectional,
            cancellationSource.Token).AsTask();
        await using IncursaStream clientStream = await openStreamTask.ConfigureAwait(false);

        await clientStream.WriteAsync(requestPayload, 0, requestPayload.Length).WaitAsync(cancellationSource.Token).ConfigureAwait(false);
        await clientStream.CompleteWritesAsync().AsTask().WaitAsync(cancellationSource.Token).ConfigureAwait(false);
        await clientStream.WritesClosed.WaitAsync(cancellationSource.Token).ConfigureAwait(false);

        await using IncursaStream serverStream = await acceptStreamTask.ConfigureAwait(false);

        byte[] requestBuffer = new byte[requestPayload.Length];
        await ReadExactlyAsync(serverStream, requestBuffer, cancellationSource.Token).ConfigureAwait(false);
        if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }

        await EnsureEofAsync(serverStream, cancellationSource.Token, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationSource.Token).ConfigureAwait(false);

        await serverStream.WriteAsync(responsePayload, 0, responsePayload.Length).WaitAsync(cancellationSource.Token).ConfigureAwait(false);
        await serverStream.CompleteWritesAsync().AsTask().WaitAsync(cancellationSource.Token).ConfigureAwait(false);
        await serverStream.WritesClosed.WaitAsync(cancellationSource.Token).ConfigureAwait(false);

        byte[] responseBuffer = new byte[responsePayload.Length];
        await ReadExactlyAsync(clientStream, responseBuffer, cancellationSource.Token).ConfigureAwait(false);
        if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
        {
            throw new InvalidOperationException("The client response payload did not match the server payload.");
        }

        await EnsureEofAsync(clientStream, cancellationSource.Token, "The client did not observe response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.WaitAsync(cancellationSource.Token).ConfigureAwait(false);
    }

    private static async Task RunSystemNetRequestResponseDisposeAsync(
        X509Certificate2 serverCertificate,
        byte[] requestPayload,
        byte[] responsePayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(listenEndPoint, serverCertificate),
            cancellationSource.Token).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                serverCertificate),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using SystemNetClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using SystemNetClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        Task<SystemNetStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationSource.Token).AsTask();
        await Task.Yield();
        Task<SystemNetStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            SystemNetStreamType.Bidirectional,
            cancellationSource.Token).AsTask();
        await using SystemNetStream clientStream = await openStreamTask.ConfigureAwait(false);

        await clientStream.WriteAsync(requestPayload, 0, requestPayload.Length).WaitAsync(cancellationSource.Token).ConfigureAwait(false);
        clientStream.CompleteWrites();
        await clientStream.WritesClosed.WaitAsync(cancellationSource.Token).ConfigureAwait(false);

        await using SystemNetStream serverStream = await acceptStreamTask.ConfigureAwait(false);

        byte[] requestBuffer = new byte[requestPayload.Length];
        await ReadExactlyAsync(serverStream, requestBuffer, cancellationSource.Token).ConfigureAwait(false);
        if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }

        await EnsureEofAsync(serverStream, cancellationSource.Token, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationSource.Token).ConfigureAwait(false);

        await serverStream.WriteAsync(responsePayload, 0, responsePayload.Length).WaitAsync(cancellationSource.Token).ConfigureAwait(false);
        serverStream.CompleteWrites();
        await serverStream.WritesClosed.WaitAsync(cancellationSource.Token).ConfigureAwait(false);

        byte[] responseBuffer = new byte[responsePayload.Length];
        await ReadExactlyAsync(clientStream, responseBuffer, cancellationSource.Token).ConfigureAwait(false);
        if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
        {
            throw new InvalidOperationException("The client response payload did not match the server payload.");
        }

        await EnsureEofAsync(clientStream, cancellationSource.Token, "The client did not observe response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.WaitAsync(cancellationSource.Token).ConfigureAwait(false);
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer, offset, buffer.Length - offset)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);

            if (bytesRead == 0)
            {
                throw new InvalidOperationException("Unexpected EOF before the full payload was read.");
            }

            offset += bytesRead;
        }
    }

    private static async Task EnsureEofAsync(Stream stream, CancellationToken cancellationToken, string failureMessage)
    {
        byte[] probe = new byte[1];
        int bytesRead = await stream.ReadAsync(probe, 0, probe.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        if (bytesRead != 0)
        {
            throw new InvalidOperationException(failureMessage);
        }
    }

    private static byte[] CreatePayload(int length, byte seed)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)((seed + index) % 251);
        }

        return payload;
    }
}
