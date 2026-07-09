// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
    private const int SequentialStreamCount = 8;

    private X509Certificate2? serverCertificate;
    private X509Certificate2? trustAnchor;
    private SslClientAuthenticationOptions? clientAuthenticationOptions;
    private SslServerAuthenticationOptions? serverAuthenticationOptions;
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
        trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        clientAuthenticationOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        serverAuthenticationOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);
        requestPayload = CreatePayload(PayloadBytes, 0x11);
        responsePayload = CreatePayload(PayloadBytes, 0x33);
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        serverAuthenticationOptions = null;
        clientAuthenticationOptions = null;
        trustAnchor?.Dispose();
        trustAnchor = null;
        serverCertificate?.Dispose();
        serverCertificate = null;
        requestPayload = null;
        responsePayload = null;
    }

    [Benchmark]
    public Task LoopbackRequestResponseDispose()
    {
        SslClientAuthenticationOptions clientOptions = clientAuthenticationOptions ?? throw new InvalidOperationException("The benchmark client authentication options have not been initialized.");
        SslServerAuthenticationOptions serverOptions = serverAuthenticationOptions ?? throw new InvalidOperationException("The benchmark server authentication options have not been initialized.");
        byte[] request = requestPayload ?? throw new InvalidOperationException("The benchmark request payload has not been initialized.");
        byte[] response = responsePayload ?? throw new InvalidOperationException("The benchmark response payload has not been initialized.");

        return Implementation switch
        {
            QuicPublicApiStreamTransferImplementation.IncursaQuic => RunIncursaRequestResponseDisposeAsync(clientOptions, serverOptions, request, response),
            QuicPublicApiStreamTransferImplementation.SystemNetQuic => RunSystemNetRequestResponseDisposeAsync(clientOptions, serverOptions, request, response),
            _ => throw new ArgumentOutOfRangeException(nameof(Implementation)),
        };
    }

    [Benchmark]
    public Task LoopbackClientUploadDispose()
    {
        SslClientAuthenticationOptions clientOptions = clientAuthenticationOptions ?? throw new InvalidOperationException("The benchmark client authentication options have not been initialized.");
        SslServerAuthenticationOptions serverOptions = serverAuthenticationOptions ?? throw new InvalidOperationException("The benchmark server authentication options have not been initialized.");
        byte[] request = requestPayload ?? throw new InvalidOperationException("The benchmark request payload has not been initialized.");

        return Implementation switch
        {
            QuicPublicApiStreamTransferImplementation.IncursaQuic => RunIncursaClientUploadDisposeAsync(clientOptions, serverOptions, request),
            QuicPublicApiStreamTransferImplementation.SystemNetQuic => RunSystemNetClientUploadDisposeAsync(clientOptions, serverOptions, request),
            _ => throw new ArgumentOutOfRangeException(nameof(Implementation)),
        };
    }

    [Benchmark]
    public Task LoopbackServerDownloadDispose()
    {
        SslClientAuthenticationOptions clientOptions = clientAuthenticationOptions ?? throw new InvalidOperationException("The benchmark client authentication options have not been initialized.");
        SslServerAuthenticationOptions serverOptions = serverAuthenticationOptions ?? throw new InvalidOperationException("The benchmark server authentication options have not been initialized.");
        byte[] response = responsePayload ?? throw new InvalidOperationException("The benchmark response payload has not been initialized.");

        return Implementation switch
        {
            QuicPublicApiStreamTransferImplementation.IncursaQuic => RunIncursaServerDownloadDisposeAsync(clientOptions, serverOptions, response),
            QuicPublicApiStreamTransferImplementation.SystemNetQuic => RunSystemNetServerDownloadDisposeAsync(clientOptions, serverOptions, response),
            _ => throw new ArgumentOutOfRangeException(nameof(Implementation)),
        };
    }

    [Benchmark]
    public Task LoopbackSequentialRequestResponseStreamsDispose()
    {
        SslClientAuthenticationOptions clientOptions = clientAuthenticationOptions ?? throw new InvalidOperationException("The benchmark client authentication options have not been initialized.");
        SslServerAuthenticationOptions serverOptions = serverAuthenticationOptions ?? throw new InvalidOperationException("The benchmark server authentication options have not been initialized.");
        byte[] request = requestPayload ?? throw new InvalidOperationException("The benchmark request payload has not been initialized.");
        byte[] response = responsePayload ?? throw new InvalidOperationException("The benchmark response payload has not been initialized.");

        return Implementation switch
        {
            QuicPublicApiStreamTransferImplementation.IncursaQuic => RunIncursaSequentialRequestResponseStreamsDisposeAsync(clientOptions, serverOptions, request, response),
            QuicPublicApiStreamTransferImplementation.SystemNetQuic => RunSystemNetSequentialRequestResponseStreamsDisposeAsync(clientOptions, serverOptions, request, response),
            _ => throw new ArgumentOutOfRangeException(nameof(Implementation)),
        };
    }

    private static async Task RunIncursaRequestResponseDisposeAsync(
        SslClientAuthenticationOptions clientAuthenticationOptions,
        SslServerAuthenticationOptions serverAuthenticationOptions,
        byte[] requestPayload,
        byte[] responsePayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(listenEndPoint, serverAuthenticationOptions),
            cancellationSource.Token).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientAuthenticationOptions),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using IncursaClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using IncursaClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await RunIncursaRequestResponseOnConnectedAsync(
            clientConnection,
            serverConnection,
            requestPayload,
            responsePayload,
            cancellationSource.Token).ConfigureAwait(false);
    }

    private static async Task RunIncursaClientUploadDisposeAsync(
        SslClientAuthenticationOptions clientAuthenticationOptions,
        SslServerAuthenticationOptions serverAuthenticationOptions,
        byte[] requestPayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(listenEndPoint, serverAuthenticationOptions),
            cancellationSource.Token).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientAuthenticationOptions),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using IncursaClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using IncursaClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await RunIncursaClientUploadOnConnectedAsync(
            clientConnection,
            serverConnection,
            requestPayload,
            cancellationSource.Token).ConfigureAwait(false);
    }

    private static async Task RunIncursaServerDownloadDisposeAsync(
        SslClientAuthenticationOptions clientAuthenticationOptions,
        SslServerAuthenticationOptions serverAuthenticationOptions,
        byte[] responsePayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(listenEndPoint, serverAuthenticationOptions),
            cancellationSource.Token).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientAuthenticationOptions),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using IncursaClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using IncursaClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await RunIncursaServerDownloadOnConnectedAsync(
            clientConnection,
            serverConnection,
            responsePayload,
            cancellationSource.Token).ConfigureAwait(false);
    }

    private static async Task RunIncursaSequentialRequestResponseStreamsDisposeAsync(
        SslClientAuthenticationOptions clientAuthenticationOptions,
        SslServerAuthenticationOptions serverAuthenticationOptions,
        byte[] requestPayload,
        byte[] responsePayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(listenEndPoint, serverAuthenticationOptions),
            cancellationSource.Token).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientAuthenticationOptions),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using IncursaClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using IncursaClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        for (int streamIndex = 0; streamIndex < SequentialStreamCount; streamIndex++)
        {
            await RunIncursaRequestResponseOnConnectedAsync(
                clientConnection,
                serverConnection,
                requestPayload,
                responsePayload,
                cancellationSource.Token).ConfigureAwait(false);
        }
    }

    private static async Task RunIncursaRequestResponseOnConnectedAsync(
        IncursaClientConnection clientConnection,
        IncursaClientConnection serverConnection,
        byte[] requestPayload,
        byte[] responsePayload,
        CancellationToken cancellationToken)
    {
        Task<IncursaStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<IncursaStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            IncursaStreamType.Bidirectional,
            cancellationToken).AsTask();
        await using IncursaStream clientStream = await openStreamTask.ConfigureAwait(false);

        await clientStream.WriteAsync(requestPayload, 0, requestPayload.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        await clientStream.CompleteWritesAsync().AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);
        await clientStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await using IncursaStream serverStream = await acceptStreamTask.ConfigureAwait(false);

        byte[] requestBuffer = new byte[requestPayload.Length];
        await ReadExactlyAsync(serverStream, requestBuffer, cancellationToken).ConfigureAwait(false);
        if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }

        await EnsureEofAsync(serverStream, cancellationToken, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await serverStream.WriteAsync(responsePayload, 0, responsePayload.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        await serverStream.CompleteWritesAsync().AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);
        await serverStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        byte[] responseBuffer = new byte[responsePayload.Length];
        await ReadExactlyAsync(clientStream, responseBuffer, cancellationToken).ConfigureAwait(false);
        if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
        {
            throw new InvalidOperationException("The client response payload did not match the server payload.");
        }

        await EnsureEofAsync(clientStream, cancellationToken, "The client did not observe response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunIncursaClientUploadOnConnectedAsync(
        IncursaClientConnection clientConnection,
        IncursaClientConnection serverConnection,
        byte[] requestPayload,
        CancellationToken cancellationToken)
    {
        Task<IncursaStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<IncursaStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            IncursaStreamType.Bidirectional,
            cancellationToken).AsTask();
        await using IncursaStream clientStream = await openStreamTask.ConfigureAwait(false);

        await clientStream.WriteAsync(requestPayload, 0, requestPayload.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        await clientStream.CompleteWritesAsync().AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);
        await clientStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await using IncursaStream serverStream = await acceptStreamTask.ConfigureAwait(false);

        byte[] requestBuffer = new byte[requestPayload.Length];
        await ReadExactlyAsync(serverStream, requestBuffer, cancellationToken).ConfigureAwait(false);
        if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }

        await EnsureEofAsync(serverStream, cancellationToken, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        await serverStream.CompleteWritesAsync().AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);
        await serverStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        await EnsureEofAsync(clientStream, cancellationToken, "The client did not observe upload response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunIncursaServerDownloadOnConnectedAsync(
        IncursaClientConnection clientConnection,
        IncursaClientConnection serverConnection,
        byte[] responsePayload,
        CancellationToken cancellationToken)
    {
        Task<IncursaStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<IncursaStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            IncursaStreamType.Bidirectional,
            cancellationToken).AsTask();
        await using IncursaStream clientStream = await openStreamTask.ConfigureAwait(false);

        await clientStream.CompleteWritesAsync().AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);
        await clientStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await using IncursaStream serverStream = await acceptStreamTask.ConfigureAwait(false);
        await EnsureEofAsync(serverStream, cancellationToken, "The server did not observe download request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await serverStream.WriteAsync(responsePayload, 0, responsePayload.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        await serverStream.CompleteWritesAsync().AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);
        await serverStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        byte[] responseBuffer = new byte[responsePayload.Length];
        await ReadExactlyAsync(clientStream, responseBuffer, cancellationToken).ConfigureAwait(false);
        if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
        {
            throw new InvalidOperationException("The client response payload did not match the server payload.");
        }

        await EnsureEofAsync(clientStream, cancellationToken, "The client did not observe response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunSystemNetRequestResponseDisposeAsync(
        SslClientAuthenticationOptions clientAuthenticationOptions,
        SslServerAuthenticationOptions serverAuthenticationOptions,
        byte[] requestPayload,
        byte[] responsePayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(listenEndPoint, serverAuthenticationOptions),
            cancellationSource.Token).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientAuthenticationOptions),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using SystemNetClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using SystemNetClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await RunSystemNetRequestResponseOnConnectedAsync(
            clientConnection,
            serverConnection,
            requestPayload,
            responsePayload,
            cancellationSource.Token).ConfigureAwait(false);
    }

    private static async Task RunSystemNetClientUploadDisposeAsync(
        SslClientAuthenticationOptions clientAuthenticationOptions,
        SslServerAuthenticationOptions serverAuthenticationOptions,
        byte[] requestPayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(listenEndPoint, serverAuthenticationOptions),
            cancellationSource.Token).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientAuthenticationOptions),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using SystemNetClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using SystemNetClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await RunSystemNetClientUploadOnConnectedAsync(
            clientConnection,
            serverConnection,
            requestPayload,
            cancellationSource.Token).ConfigureAwait(false);
    }

    private static async Task RunSystemNetServerDownloadDisposeAsync(
        SslClientAuthenticationOptions clientAuthenticationOptions,
        SslServerAuthenticationOptions serverAuthenticationOptions,
        byte[] responsePayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(listenEndPoint, serverAuthenticationOptions),
            cancellationSource.Token).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientAuthenticationOptions),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using SystemNetClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using SystemNetClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await RunSystemNetServerDownloadOnConnectedAsync(
            clientConnection,
            serverConnection,
            responsePayload,
            cancellationSource.Token).ConfigureAwait(false);
    }

    private static async Task RunSystemNetSequentialRequestResponseStreamsDisposeAsync(
        SslClientAuthenticationOptions clientAuthenticationOptions,
        SslServerAuthenticationOptions serverAuthenticationOptions,
        byte[] requestPayload,
        byte[] responsePayload)
    {
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromSeconds(60));
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(listenEndPoint, serverAuthenticationOptions),
            cancellationSource.Token).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptConnectionTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientAuthenticationOptions),
            cancellationSource.Token).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask).ConfigureAwait(false);

        await using SystemNetClientConnection serverConnection = await acceptConnectionTask.ConfigureAwait(false);
        await using SystemNetClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        for (int streamIndex = 0; streamIndex < SequentialStreamCount; streamIndex++)
        {
            await RunSystemNetRequestResponseOnConnectedAsync(
                clientConnection,
                serverConnection,
                requestPayload,
                responsePayload,
                cancellationSource.Token).ConfigureAwait(false);
        }
    }

    private static async Task RunSystemNetRequestResponseOnConnectedAsync(
        SystemNetClientConnection clientConnection,
        SystemNetClientConnection serverConnection,
        byte[] requestPayload,
        byte[] responsePayload,
        CancellationToken cancellationToken)
    {
        Task<SystemNetStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<SystemNetStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            SystemNetStreamType.Bidirectional,
            cancellationToken).AsTask();
        await using SystemNetStream clientStream = await openStreamTask.ConfigureAwait(false);

        await clientStream.WriteAsync(requestPayload, 0, requestPayload.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        clientStream.CompleteWrites();
        await clientStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await using SystemNetStream serverStream = await acceptStreamTask.ConfigureAwait(false);

        byte[] requestBuffer = new byte[requestPayload.Length];
        await ReadExactlyAsync(serverStream, requestBuffer, cancellationToken).ConfigureAwait(false);
        if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }

        await EnsureEofAsync(serverStream, cancellationToken, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await serverStream.WriteAsync(responsePayload, 0, responsePayload.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        serverStream.CompleteWrites();
        await serverStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        byte[] responseBuffer = new byte[responsePayload.Length];
        await ReadExactlyAsync(clientStream, responseBuffer, cancellationToken).ConfigureAwait(false);
        if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
        {
            throw new InvalidOperationException("The client response payload did not match the server payload.");
        }

        await EnsureEofAsync(clientStream, cancellationToken, "The client did not observe response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunSystemNetClientUploadOnConnectedAsync(
        SystemNetClientConnection clientConnection,
        SystemNetClientConnection serverConnection,
        byte[] requestPayload,
        CancellationToken cancellationToken)
    {
        Task<SystemNetStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<SystemNetStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            SystemNetStreamType.Bidirectional,
            cancellationToken).AsTask();
        await using SystemNetStream clientStream = await openStreamTask.ConfigureAwait(false);

        await clientStream.WriteAsync(requestPayload, 0, requestPayload.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        clientStream.CompleteWrites();
        await clientStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await using SystemNetStream serverStream = await acceptStreamTask.ConfigureAwait(false);

        byte[] requestBuffer = new byte[requestPayload.Length];
        await ReadExactlyAsync(serverStream, requestBuffer, cancellationToken).ConfigureAwait(false);
        if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }

        await EnsureEofAsync(serverStream, cancellationToken, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        serverStream.CompleteWrites();
        await serverStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        await EnsureEofAsync(clientStream, cancellationToken, "The client did not observe upload response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunSystemNetServerDownloadOnConnectedAsync(
        SystemNetClientConnection clientConnection,
        SystemNetClientConnection serverConnection,
        byte[] responsePayload,
        CancellationToken cancellationToken)
    {
        Task<SystemNetStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<SystemNetStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
            SystemNetStreamType.Bidirectional,
            cancellationToken).AsTask();
        await using SystemNetStream clientStream = await openStreamTask.ConfigureAwait(false);

        clientStream.CompleteWrites();
        await clientStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await using SystemNetStream serverStream = await acceptStreamTask.ConfigureAwait(false);
        await EnsureEofAsync(serverStream, cancellationToken, "The server did not observe download request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        await serverStream.WriteAsync(responsePayload, 0, responsePayload.Length).WaitAsync(cancellationToken).ConfigureAwait(false);
        serverStream.CompleteWrites();
        await serverStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);

        byte[] responseBuffer = new byte[responsePayload.Length];
        await ReadExactlyAsync(clientStream, responseBuffer, cancellationToken).ConfigureAwait(false);
        if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
        {
            throw new InvalidOperationException("The client response payload did not match the server payload.");
        }

        await EnsureEofAsync(clientStream, cancellationToken, "The client did not observe response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
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
