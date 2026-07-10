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
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
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

public enum QuicPublicApiLifecyclePhaseImplementation
{
    IncursaQuic,
    SystemNetQuic,
}

public enum QuicPublicApiLifecyclePhase
{
    ListenerSetup,
    ConnectAcceptHandshake,
    StreamOpenAccept,
    RequestWriteRead,
    RequestFin,
    ConnectionClose,
    DisposeResources,
}

public sealed record QuicPublicApiLifecyclePhaseBenchmarkCase(
    QuicPublicApiLifecyclePhaseImplementation Implementation,
    QuicPublicApiLifecyclePhase Phase);

public sealed class QuicPublicApiLifecyclePhaseBenchmarksConfig : ManualConfig
{
    public QuicPublicApiLifecyclePhaseBenchmarksConfig()
    {
        AddJob(Job.ShortRun.WithInvocationCount(1).WithUnrollFactor(1));
    }
}

/// <summary>
/// Benchmarks matched public-facade QUIC lifecycle phases against Incursa.Quic and System.Net.Quic.
/// </summary>
[Config(typeof(QuicPublicApiLifecyclePhaseBenchmarksConfig))]
[MemoryDiagnoser]
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public class QuicPublicApiLifecyclePhaseBenchmarks
{
    private const int RequestPayloadBytes = 1024;

    private CancellationTokenSource? cancellationSource;
    private X509Certificate2? serverCertificate;
    private X509Certificate2? trustAnchor;
    private SslClientAuthenticationOptions? clientAuthenticationOptions;
    private SslServerAuthenticationOptions? serverAuthenticationOptions;
    private byte[]? requestPayload;
    private byte[]? requestBuffer;
    private byte[]? eofProbe;

    private IPEndPoint? incursaListenEndPoint;
    private IPEndPoint? systemNetListenEndPoint;
    private IncursaListener? incursaListener;
    private IncursaClientConnection? incursaClientConnection;
    private IncursaClientConnection? incursaServerConnection;
    private IncursaStream? incursaClientStream;
    private IncursaStream? incursaServerStream;
    private SystemNetListener? systemNetListener;
    private SystemNetClientConnection? systemNetClientConnection;
    private SystemNetClientConnection? systemNetServerConnection;
    private SystemNetStream? systemNetClientStream;
    private SystemNetStream? systemNetServerStream;

    [ParamsSource(nameof(GetSupportedCases))]
    public QuicPublicApiLifecyclePhaseBenchmarkCase BenchmarkCase { get; set; } = new(
        QuicPublicApiLifecyclePhaseImplementation.IncursaQuic,
        QuicPublicApiLifecyclePhase.ListenerSetup);

    private QuicPublicApiLifecyclePhaseImplementation Implementation => BenchmarkCase.Implementation;

    private QuicPublicApiLifecyclePhase Phase => BenchmarkCase.Phase;

    public IEnumerable<QuicPublicApiLifecyclePhaseBenchmarkCase> GetSupportedCases()
    {
        foreach (QuicPublicApiLifecyclePhaseImplementation implementation in GetSupportedImplementations())
        {
            foreach (QuicPublicApiLifecyclePhase phase in GetSupportedPhases())
            {
                if (implementation == QuicPublicApiLifecyclePhaseImplementation.SystemNetQuic
                    && phase != QuicPublicApiLifecyclePhase.ListenerSetup
                    && phase != QuicPublicApiLifecyclePhase.ConnectAcceptHandshake)
                {
                    Console.WriteLine(
                        "Skipping System.Net.Quic lifecycle rows beyond connect/accept/handshake because the matched public stream phase does not complete in isolation in this benchmark surface.");
                    continue;
                }

                yield return new QuicPublicApiLifecyclePhaseBenchmarkCase(implementation, phase);
            }
        }
    }

    public IEnumerable<QuicPublicApiLifecyclePhaseImplementation> GetSupportedImplementations()
    {
        if (IncursaClientConnection.IsSupported && IncursaListener.IsSupported)
        {
            yield return QuicPublicApiLifecyclePhaseImplementation.IncursaQuic;
        }
        else
        {
            Console.WriteLine(
                $"Skipping Incursa.Quic public lifecycle-phase benchmarks because support markers are not both true. QuicConnection.IsSupported={IncursaClientConnection.IsSupported}, QuicListener.IsSupported={IncursaListener.IsSupported}.");
        }

        if (SystemNetClientConnection.IsSupported && SystemNetListener.IsSupported)
        {
            yield return QuicPublicApiLifecyclePhaseImplementation.SystemNetQuic;
        }
        else
        {
            Console.WriteLine(
                $"Skipping System.Net.Quic public lifecycle-phase benchmarks because support markers are not both true. QuicConnection.IsSupported={SystemNetClientConnection.IsSupported}, QuicListener.IsSupported={SystemNetListener.IsSupported}.");
        }
    }

    public IEnumerable<QuicPublicApiLifecyclePhase> GetSupportedPhases()
    {
        yield return QuicPublicApiLifecyclePhase.ListenerSetup;
        yield return QuicPublicApiLifecyclePhase.ConnectAcceptHandshake;
        yield return QuicPublicApiLifecyclePhase.StreamOpenAccept;
        yield return QuicPublicApiLifecyclePhase.RequestWriteRead;
        yield return QuicPublicApiLifecyclePhase.RequestFin;
        yield return QuicPublicApiLifecyclePhase.ConnectionClose;
        yield return QuicPublicApiLifecyclePhase.DisposeResources;
    }

    [GlobalSetup]
    public void GlobalSetup()
    {
        cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        clientAuthenticationOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        serverAuthenticationOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);
        requestPayload = CreatePayload(RequestPayloadBytes, 0x11);
        requestBuffer = new byte[RequestPayloadBytes];
        eofProbe = new byte[1];
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        CleanupIterationResourcesAsync().GetAwaiter().GetResult();

        eofProbe = null;
        requestBuffer = null;
        requestPayload = null;
        serverAuthenticationOptions = null;
        clientAuthenticationOptions = null;
        trustAnchor?.Dispose();
        trustAnchor = null;
        serverCertificate?.Dispose();
        serverCertificate = null;
        cancellationSource?.Dispose();
        cancellationSource = null;
    }

    [IterationSetup]
    public void IterationSetup()
    {
        PrepareIterationAsync().GetAwaiter().GetResult();
    }

    [IterationCleanup]
    public void IterationCleanup()
    {
        CleanupIterationResourcesAsync().GetAwaiter().GetResult();
    }

    [Benchmark]
    public Task MeasureLifecyclePhase()
    {
        return Implementation switch
        {
            QuicPublicApiLifecyclePhaseImplementation.IncursaQuic => RunIncursaLifecyclePhaseAsync(),
            QuicPublicApiLifecyclePhaseImplementation.SystemNetQuic => RunSystemNetLifecyclePhaseAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(Implementation)),
        };
    }

    private async Task PrepareIterationAsync()
    {
        switch (Implementation)
        {
            case QuicPublicApiLifecyclePhaseImplementation.IncursaQuic:
                await PrepareIncursaIterationAsync().ConfigureAwait(false);
                break;
            case QuicPublicApiLifecyclePhaseImplementation.SystemNetQuic:
                await PrepareSystemNetIterationAsync().ConfigureAwait(false);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(Implementation));
        }
    }

    private async Task PrepareIncursaIterationAsync()
    {
        SslClientAuthenticationOptions clientOptions = GetClientAuthenticationOptions();
        SslServerAuthenticationOptions serverOptions = GetServerAuthenticationOptions();
        CancellationToken cancellationToken = GetCancellationToken();

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.ConnectAcceptHandshake)
        {
            await EnsureIncursaListenerAsync(serverOptions, cancellationToken).ConfigureAwait(false);
        }

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.StreamOpenAccept)
        {
            await EnsureIncursaConnectionPairAsync(clientOptions, cancellationToken).ConfigureAwait(false);
        }

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.RequestWriteRead)
        {
            await EnsureIncursaStreamPairAsync(cancellationToken).ConfigureAwait(false);
        }

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.RequestFin)
        {
            await RunIncursaRequestWriteReadAsync(cancellationToken).ConfigureAwait(false);
        }

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.ConnectionClose)
        {
            await RunIncursaRequestFinAsync(cancellationToken).ConfigureAwait(false);
        }

        if (Phase == QuicPublicApiLifecyclePhase.DisposeResources)
        {
            await RunIncursaConnectionCloseAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task PrepareSystemNetIterationAsync()
    {
        SslClientAuthenticationOptions clientOptions = GetClientAuthenticationOptions();
        SslServerAuthenticationOptions serverOptions = GetServerAuthenticationOptions();
        CancellationToken cancellationToken = GetCancellationToken();

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.ConnectAcceptHandshake)
        {
            await EnsureSystemNetListenerAsync(serverOptions, cancellationToken).ConfigureAwait(false);
        }

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.StreamOpenAccept)
        {
            await EnsureSystemNetConnectionPairAsync(clientOptions, cancellationToken).ConfigureAwait(false);
        }

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.RequestWriteRead)
        {
            await EnsureSystemNetStreamPairAsync(cancellationToken).ConfigureAwait(false);
        }

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.RequestFin)
        {
            await RunSystemNetRequestWriteReadAsync(cancellationToken).ConfigureAwait(false);
        }

        if ((int)Phase >= (int)QuicPublicApiLifecyclePhase.ConnectionClose)
        {
            await RunSystemNetRequestFinAsync(cancellationToken).ConfigureAwait(false);
        }

        if (Phase == QuicPublicApiLifecyclePhase.DisposeResources)
        {
            await RunSystemNetConnectionCloseAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private Task RunIncursaLifecyclePhaseAsync()
    {
        CancellationToken cancellationToken = GetCancellationToken();

        return Phase switch
        {
            QuicPublicApiLifecyclePhase.ListenerSetup => RunIncursaListenerSetupAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.ConnectAcceptHandshake => RunIncursaConnectAcceptHandshakeAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.StreamOpenAccept => RunIncursaStreamOpenAcceptAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.RequestWriteRead => RunIncursaRequestWriteReadAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.RequestFin => RunIncursaRequestFinAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.ConnectionClose => RunIncursaConnectionCloseAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.DisposeResources => RunIncursaDisposeResourcesAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(Phase)),
        };
    }

    private Task RunSystemNetLifecyclePhaseAsync()
    {
        CancellationToken cancellationToken = GetCancellationToken();

        return Phase switch
        {
            QuicPublicApiLifecyclePhase.ListenerSetup => RunSystemNetListenerSetupAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.ConnectAcceptHandshake => RunSystemNetConnectAcceptHandshakeAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.StreamOpenAccept => RunSystemNetStreamOpenAcceptAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.RequestWriteRead => RunSystemNetRequestWriteReadAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.RequestFin => RunSystemNetRequestFinAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.ConnectionClose => RunSystemNetConnectionCloseAsync(cancellationToken),
            QuicPublicApiLifecyclePhase.DisposeResources => RunSystemNetDisposeResourcesAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(Phase)),
        };
    }

    private async Task CleanupIterationResourcesAsync()
    {
        switch (Implementation)
        {
            case QuicPublicApiLifecyclePhaseImplementation.IncursaQuic:
                await CleanupIncursaIterationResourcesAsync().ConfigureAwait(false);
                break;
            case QuicPublicApiLifecyclePhaseImplementation.SystemNetQuic:
                await CleanupSystemNetIterationResourcesAsync().ConfigureAwait(false);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(Implementation));
        }
    }

    private async Task CleanupIncursaIterationResourcesAsync()
    {
        if (incursaClientStream is not null)
        {
            await incursaClientStream.DisposeAsync().ConfigureAwait(false);
            incursaClientStream = null;
        }

        if (incursaServerStream is not null)
        {
            await incursaServerStream.DisposeAsync().ConfigureAwait(false);
            incursaServerStream = null;
        }

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

        incursaListenEndPoint = null;
    }

    private async Task CleanupSystemNetIterationResourcesAsync()
    {
        if (systemNetClientStream is not null)
        {
            await systemNetClientStream.DisposeAsync().ConfigureAwait(false);
            systemNetClientStream = null;
        }

        if (systemNetServerStream is not null)
        {
            await systemNetServerStream.DisposeAsync().ConfigureAwait(false);
            systemNetServerStream = null;
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

        systemNetListenEndPoint = null;
    }

    private async Task RunIncursaListenerSetupAsync(CancellationToken cancellationToken)
    {
        SslServerAuthenticationOptions serverOptions = GetServerAuthenticationOptions();
        incursaListenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();
        incursaListener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(incursaListenEndPoint, serverOptions),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task RunSystemNetListenerSetupAsync(CancellationToken cancellationToken)
    {
        SslServerAuthenticationOptions serverOptions = GetServerAuthenticationOptions();
        systemNetListenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();
        systemNetListener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(systemNetListenEndPoint, serverOptions),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task RunIncursaConnectAcceptHandshakeAsync(CancellationToken cancellationToken)
    {
        await EnsureIncursaConnectionPairAsync(GetClientAuthenticationOptions(), cancellationToken).ConfigureAwait(false);
    }

    private async Task RunSystemNetConnectAcceptHandshakeAsync(CancellationToken cancellationToken)
    {
        await EnsureSystemNetConnectionPairAsync(GetClientAuthenticationOptions(), cancellationToken).ConfigureAwait(false);
    }

    private async Task RunIncursaStreamOpenAcceptAsync(CancellationToken cancellationToken)
    {
        await EnsureIncursaStreamPairAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task RunSystemNetStreamOpenAcceptAsync(CancellationToken cancellationToken)
    {
        await EnsureSystemNetStreamPairAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task RunIncursaRequestWriteReadAsync(CancellationToken cancellationToken)
    {
        IncursaStream clientStream = incursaClientStream ?? throw new InvalidOperationException("The Incursa.Quic client stream has not been initialized.");
        IncursaStream serverStream = incursaServerStream ?? throw new InvalidOperationException("The Incursa.Quic server stream has not been initialized.");
        byte[] payload = requestPayload ?? throw new InvalidOperationException("The benchmark request payload has not been initialized.");
        byte[] buffer = requestBuffer ?? throw new InvalidOperationException("The benchmark request buffer has not been initialized.");

        await clientStream.WriteAsync(payload.AsMemory(), cancellationToken).ConfigureAwait(false);
        await ReadExactlyAsync(serverStream, buffer, cancellationToken).ConfigureAwait(false);

        if (!payload.AsSpan().SequenceEqual(buffer.AsSpan(0, payload.Length)))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }
    }

    private async Task RunSystemNetRequestWriteReadAsync(CancellationToken cancellationToken)
    {
        SystemNetStream clientStream = systemNetClientStream ?? throw new InvalidOperationException("The System.Net.Quic client stream has not been initialized.");
        SystemNetStream serverStream = systemNetServerStream ?? throw new InvalidOperationException("The System.Net.Quic server stream has not been initialized.");
        byte[] payload = requestPayload ?? throw new InvalidOperationException("The benchmark request payload has not been initialized.");
        byte[] buffer = requestBuffer ?? throw new InvalidOperationException("The benchmark request buffer has not been initialized.");

        await clientStream.WriteAsync(payload.AsMemory(), cancellationToken).ConfigureAwait(false);
        await ReadExactlyAsync(serverStream, buffer, cancellationToken).ConfigureAwait(false);

        if (!payload.AsSpan().SequenceEqual(buffer.AsSpan(0, payload.Length)))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }
    }

    private async Task RunIncursaRequestFinAsync(CancellationToken cancellationToken)
    {
        IncursaStream clientStream = incursaClientStream ?? throw new InvalidOperationException("The Incursa.Quic client stream has not been initialized.");
        IncursaStream serverStream = incursaServerStream ?? throw new InvalidOperationException("The Incursa.Quic server stream has not been initialized.");
        byte[] probe = eofProbe ?? throw new InvalidOperationException("The benchmark EOF probe has not been initialized.");

        await clientStream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);
        await clientStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        await EnsureEofAsync(serverStream, probe, cancellationToken, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task RunSystemNetRequestFinAsync(CancellationToken cancellationToken)
    {
        SystemNetStream clientStream = systemNetClientStream ?? throw new InvalidOperationException("The System.Net.Quic client stream has not been initialized.");
        SystemNetStream serverStream = systemNetServerStream ?? throw new InvalidOperationException("The System.Net.Quic server stream has not been initialized.");
        byte[] probe = eofProbe ?? throw new InvalidOperationException("The benchmark EOF probe has not been initialized.");

        clientStream.CompleteWrites();
        await clientStream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        await EnsureEofAsync(serverStream, probe, cancellationToken, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task RunIncursaConnectionCloseAsync(CancellationToken cancellationToken)
    {
        IncursaClientConnection clientConnection = incursaClientConnection ?? throw new InvalidOperationException("The Incursa.Quic client connection has not been initialized.");
        IncursaClientConnection serverConnection = incursaServerConnection ?? throw new InvalidOperationException("The Incursa.Quic server connection has not been initialized.");

        await serverConnection.CloseAsync(0, cancellationToken).ConfigureAwait(false);
        await clientConnection.CloseAsync(0, cancellationToken).ConfigureAwait(false);
    }

    private async Task RunSystemNetConnectionCloseAsync(CancellationToken cancellationToken)
    {
        SystemNetClientConnection clientConnection = systemNetClientConnection ?? throw new InvalidOperationException("The System.Net.Quic client connection has not been initialized.");
        SystemNetClientConnection serverConnection = systemNetServerConnection ?? throw new InvalidOperationException("The System.Net.Quic server connection has not been initialized.");

        await serverConnection.CloseAsync(0, cancellationToken).ConfigureAwait(false);
        await clientConnection.CloseAsync(0, cancellationToken).ConfigureAwait(false);
    }

    private async Task RunIncursaDisposeResourcesAsync()
    {
        await CleanupIncursaIterationResourcesAsync().ConfigureAwait(false);
    }

    private async Task RunSystemNetDisposeResourcesAsync()
    {
        await CleanupSystemNetIterationResourcesAsync().ConfigureAwait(false);
    }

    private async Task EnsureIncursaListenerAsync(
        SslServerAuthenticationOptions serverOptions,
        CancellationToken cancellationToken)
    {
        if (incursaListener is not null)
        {
            return;
        }

        incursaListenEndPoint ??= QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();
        incursaListener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(incursaListenEndPoint, serverOptions),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task EnsureSystemNetListenerAsync(
        SslServerAuthenticationOptions serverOptions,
        CancellationToken cancellationToken)
    {
        if (systemNetListener is not null)
        {
            return;
        }

        systemNetListenEndPoint ??= QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();
        systemNetListener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(systemNetListenEndPoint, serverOptions),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task EnsureIncursaConnectionPairAsync(
        SslClientAuthenticationOptions clientOptions,
        CancellationToken cancellationToken)
    {
        if (incursaClientConnection is not null || incursaServerConnection is not null)
        {
            return;
        }

        if (incursaListener is null || incursaListenEndPoint is null)
        {
            throw new InvalidOperationException("The Incursa.Quic listener has not been initialized.");
        }

        Task<IncursaClientConnection> acceptTask = incursaListener.AcceptConnectionAsync(cancellationToken).AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, incursaListenEndPoint.Port),
                clientOptions),
            cancellationToken).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);
        incursaServerConnection = await acceptTask.ConfigureAwait(false);
        incursaClientConnection = await connectTask.ConfigureAwait(false);
    }

    private async Task EnsureSystemNetConnectionPairAsync(
        SslClientAuthenticationOptions clientOptions,
        CancellationToken cancellationToken)
    {
        if (systemNetClientConnection is not null || systemNetServerConnection is not null)
        {
            return;
        }

        if (systemNetListener is null || systemNetListenEndPoint is null)
        {
            throw new InvalidOperationException("The System.Net.Quic listener has not been initialized.");
        }

        Task<SystemNetClientConnection> acceptTask = systemNetListener.AcceptConnectionAsync(cancellationToken).AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, systemNetListenEndPoint.Port),
                clientOptions),
            cancellationToken).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);
        systemNetServerConnection = await acceptTask.ConfigureAwait(false);
        systemNetClientConnection = await connectTask.ConfigureAwait(false);
    }

    private async Task EnsureIncursaStreamPairAsync(CancellationToken cancellationToken)
    {
        if (incursaClientStream is not null || incursaServerStream is not null)
        {
            return;
        }

        if (incursaClientConnection is null || incursaServerConnection is null)
        {
            throw new InvalidOperationException("The Incursa.Quic connection pair has not been initialized.");
        }

        Task<IncursaStream> acceptTask = incursaServerConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<IncursaStream> openTask = incursaClientConnection.OpenOutboundStreamAsync(
            IncursaStreamType.Bidirectional,
            cancellationToken).AsTask();

        incursaClientStream = await openTask.ConfigureAwait(false);
        incursaServerStream = await acceptTask.ConfigureAwait(false);
    }

    private async Task EnsureSystemNetStreamPairAsync(CancellationToken cancellationToken)
    {
        if (systemNetClientStream is not null || systemNetServerStream is not null)
        {
            return;
        }

        if (systemNetClientConnection is null || systemNetServerConnection is null)
        {
            throw new InvalidOperationException("The System.Net.Quic connection pair has not been initialized.");
        }

        Task<SystemNetStream> acceptTask = systemNetServerConnection.AcceptInboundStreamAsync(cancellationToken).AsTask();
        await Task.Yield();
        Task<SystemNetStream> openTask = systemNetClientConnection.OpenOutboundStreamAsync(
            SystemNetStreamType.Bidirectional,
            cancellationToken).AsTask();

        systemNetClientStream = await openTask.ConfigureAwait(false);
        await systemNetClientStream.WriteAsync(ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
        systemNetServerStream = await acceptTask.ConfigureAwait(false);
    }

    private SslClientAuthenticationOptions GetClientAuthenticationOptions()
    {
        return clientAuthenticationOptions ?? throw new InvalidOperationException("The benchmark client authentication options have not been initialized.");
    }

    private SslServerAuthenticationOptions GetServerAuthenticationOptions()
    {
        return serverAuthenticationOptions ?? throw new InvalidOperationException("The benchmark server authentication options have not been initialized.");
    }

    private CancellationToken GetCancellationToken()
    {
        return cancellationSource?.Token
            ?? throw new InvalidOperationException("The benchmark cancellation source has not been initialized.");
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                throw new InvalidOperationException("Unexpected EOF before the full payload was read.");
            }

            offset += bytesRead;
        }
    }

    private static async Task EnsureEofAsync(
        Stream stream,
        byte[] probe,
        CancellationToken cancellationToken,
        string failureMessage)
    {
        int bytesRead = await stream.ReadAsync(probe.AsMemory(), cancellationToken).ConfigureAwait(false);
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
