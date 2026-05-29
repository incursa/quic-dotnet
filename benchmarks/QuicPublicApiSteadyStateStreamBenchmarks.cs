// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using IncursaClientConnection = global::Incursa.Quic.QuicConnection;
using IncursaListener = global::Incursa.Quic.QuicListener;
using IncursaStream = global::Incursa.Quic.QuicStream;
using IncursaStreamType = global::Incursa.Quic.QuicStreamType;
using SystemNetClientConnection = global::System.Net.Quic.QuicConnection;
using SystemNetListener = global::System.Net.Quic.QuicListener;
using SystemNetStream = global::System.Net.Quic.QuicStream;
using SystemNetStreamType = global::System.Net.Quic.QuicStreamType;

namespace Incursa.Quic.Benchmarks;

public enum QuicPublicApiSteadyStateStreamImplementation
{
    IncursaQuic,
    SystemNetQuic,
}

/// <summary>
/// Benchmarks repeated stream request/response transfers on an already-established public QUIC connection.
/// </summary>
[MemoryDiagnoser]
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public class QuicPublicApiSteadyStateStreamBenchmarks
{
    private const int PayloadBytes = 1024;

    private CancellationTokenSource? cancellationSource;
    private X509Certificate2? serverCertificate;
    private X509Certificate2? trustAnchor;
    private SslClientAuthenticationOptions? clientAuthenticationOptions;
    private SslServerAuthenticationOptions? serverAuthenticationOptions;
    private byte[]? requestPayload;
    private byte[]? responsePayload;
    private IncursaListener? incursaListener;
    private IncursaClientConnection? incursaClientConnection;
    private IncursaClientConnection? incursaServerConnection;
    private SystemNetListener? systemNetListener;
    private SystemNetClientConnection? systemNetClientConnection;
    private SystemNetClientConnection? systemNetServerConnection;

    [ParamsSource(nameof(GetSupportedImplementations))]
    public QuicPublicApiSteadyStateStreamImplementation Implementation { get; set; }

    public IEnumerable<QuicPublicApiSteadyStateStreamImplementation> GetSupportedImplementations()
    {
        if (IncursaClientConnection.IsSupported && IncursaListener.IsSupported)
        {
            yield return QuicPublicApiSteadyStateStreamImplementation.IncursaQuic;
        }
        else
        {
            Console.WriteLine(
                $"Skipping Incursa.Quic steady-state stream benchmarks because support markers are not both true. QuicConnection.IsSupported={IncursaClientConnection.IsSupported}, QuicListener.IsSupported={IncursaListener.IsSupported}.");
        }

        if (SystemNetClientConnection.IsSupported && SystemNetListener.IsSupported)
        {
            yield return QuicPublicApiSteadyStateStreamImplementation.SystemNetQuic;
        }
        else
        {
            Console.WriteLine(
                $"Skipping System.Net.Quic steady-state stream benchmarks because support markers are not both true. QuicConnection.IsSupported={SystemNetClientConnection.IsSupported}, QuicListener.IsSupported={SystemNetListener.IsSupported}.");
        }
    }

    [GlobalSetup]
    public void GlobalSetup()
    {
        cancellationSource = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        clientAuthenticationOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        serverAuthenticationOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);
        requestPayload = CreatePayload(PayloadBytes, 0x11);
        responsePayload = CreatePayload(PayloadBytes, 0x33);

        GlobalSetupAsync().GetAwaiter().GetResult();
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        GlobalCleanupAsync().GetAwaiter().GetResult();

        serverAuthenticationOptions = null;
        clientAuthenticationOptions = null;
        trustAnchor?.Dispose();
        trustAnchor = null;
        serverCertificate?.Dispose();
        serverCertificate = null;
        requestPayload = null;
        responsePayload = null;
        cancellationSource?.Dispose();
        cancellationSource = null;
    }

    [Benchmark]
    public Task LoopbackRequestResponseOnEstablishedConnection()
    {
        byte[] request = requestPayload ?? throw new InvalidOperationException("The benchmark request payload has not been initialized.");
        byte[] response = responsePayload ?? throw new InvalidOperationException("The benchmark response payload has not been initialized.");
        CancellationToken cancellationToken = cancellationSource?.Token
            ?? throw new InvalidOperationException("The benchmark cancellation source has not been initialized.");

        return Implementation switch
        {
            QuicPublicApiSteadyStateStreamImplementation.IncursaQuic => RunIncursaRequestResponseAsync(request, response, cancellationToken),
            QuicPublicApiSteadyStateStreamImplementation.SystemNetQuic => RunSystemNetRequestResponseAsync(request, response, cancellationToken),
            _ => throw new ArgumentOutOfRangeException(nameof(Implementation)),
        };
    }

    private async Task GlobalSetupAsync()
    {
        SslClientAuthenticationOptions clientOptions = clientAuthenticationOptions ?? throw new InvalidOperationException("The benchmark client authentication options have not been initialized.");
        SslServerAuthenticationOptions serverOptions = serverAuthenticationOptions ?? throw new InvalidOperationException("The benchmark server authentication options have not been initialized.");
        CancellationToken cancellationToken = cancellationSource?.Token
            ?? throw new InvalidOperationException("The benchmark cancellation source has not been initialized.");
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        switch (Implementation)
        {
            case QuicPublicApiSteadyStateStreamImplementation.IncursaQuic:
                incursaListener = await IncursaListener.ListenAsync(
                    QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(listenEndPoint, serverOptions),
                    cancellationToken).ConfigureAwait(false);
                Task<IncursaClientConnection> incursaAcceptTask = incursaListener.AcceptConnectionAsync(cancellationToken).AsTask();
                Task<IncursaClientConnection> incursaConnectTask = IncursaClientConnection.ConnectAsync(
                    QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                        new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                        clientOptions),
                    cancellationToken).AsTask();
                await Task.WhenAll(incursaAcceptTask, incursaConnectTask).ConfigureAwait(false);
                incursaServerConnection = await incursaAcceptTask.ConfigureAwait(false);
                incursaClientConnection = await incursaConnectTask.ConfigureAwait(false);
                break;

            case QuicPublicApiSteadyStateStreamImplementation.SystemNetQuic:
                systemNetListener = await SystemNetListener.ListenAsync(
                    QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(listenEndPoint, serverOptions),
                    cancellationToken).ConfigureAwait(false);
                Task<SystemNetClientConnection> systemNetAcceptTask = systemNetListener.AcceptConnectionAsync(cancellationToken).AsTask();
                Task<SystemNetClientConnection> systemNetConnectTask = SystemNetClientConnection.ConnectAsync(
                    QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                        new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                        clientOptions),
                    cancellationToken).AsTask();
                await Task.WhenAll(systemNetAcceptTask, systemNetConnectTask).ConfigureAwait(false);
                systemNetServerConnection = await systemNetAcceptTask.ConfigureAwait(false);
                systemNetClientConnection = await systemNetConnectTask.ConfigureAwait(false);
                break;
        }
    }

    private async Task GlobalCleanupAsync()
    {
        if (incursaClientConnection is not null)
        {
            await incursaClientConnection.DisposeAsync().ConfigureAwait(false);
            incursaClientConnection = null;
        }

        if (incursaServerConnection is not null)
        {
            await incursaServerConnection.DisposeAsync().ConfigureAwait(false);
            incursaServerConnection = null;
        }

        if (incursaListener is not null)
        {
            await incursaListener.DisposeAsync().ConfigureAwait(false);
            incursaListener = null;
        }

        if (systemNetClientConnection is not null)
        {
            await systemNetClientConnection.DisposeAsync().ConfigureAwait(false);
            systemNetClientConnection = null;
        }

        if (systemNetServerConnection is not null)
        {
            await systemNetServerConnection.DisposeAsync().ConfigureAwait(false);
            systemNetServerConnection = null;
        }

        if (systemNetListener is not null)
        {
            await systemNetListener.DisposeAsync().ConfigureAwait(false);
            systemNetListener = null;
        }
    }

    private async Task RunIncursaRequestResponseAsync(
        byte[] requestPayload,
        byte[] responsePayload,
        CancellationToken cancellationToken)
    {
        IncursaClientConnection clientConnection = incursaClientConnection ?? throw new InvalidOperationException("The Incursa.Quic client connection has not been initialized.");
        IncursaClientConnection serverConnection = incursaServerConnection ?? throw new InvalidOperationException("The Incursa.Quic server connection has not been initialized.");

        Task<IncursaStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        await using IncursaStream clientStream = await clientConnection.OpenOutboundStreamAsync(
            IncursaStreamType.Bidirectional,
            cancellationToken).ConfigureAwait(false);

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

    private async Task RunSystemNetRequestResponseAsync(
        byte[] requestPayload,
        byte[] responsePayload,
        CancellationToken cancellationToken)
    {
        SystemNetClientConnection clientConnection = systemNetClientConnection ?? throw new InvalidOperationException("The System.Net.Quic client connection has not been initialized.");
        SystemNetClientConnection serverConnection = systemNetServerConnection ?? throw new InvalidOperationException("The System.Net.Quic server connection has not been initialized.");

        Task<SystemNetStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        await using SystemNetStream clientStream = await clientConnection.OpenOutboundStreamAsync(
            SystemNetStreamType.Bidirectional,
            cancellationToken).ConfigureAwait(false);

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
