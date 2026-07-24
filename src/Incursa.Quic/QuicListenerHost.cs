// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace Incursa.Quic;

internal sealed class QuicListenerHost : IAsyncDisposable, IDisposable
{
    private static readonly uint[] ListenerSupportedVersions =
    [
        QuicVersionNegotiation.Version1,
        QuicVersionNegotiation.Version2,
    ];
    private const int BitsPerByte = 8;
    private const int RouteConnectionIdLength = 8;
    private const ulong MinimumActiveConnectionIdLimit = 2;
    private const int RetryBootstrapReplayValidationFailureParseHeader = 2;
    private const int RetryBootstrapReplayValidationFailureVersionOrType = 3;
    private const int RetryBootstrapReplayValidationFailureDestinationConnectionIdMismatch = 4;
    private const int RetryBootstrapReplayValidationFailureTokenParse = 5;
    private const int RetryBootstrapReplayValidationFailureTokenMismatch = 6;
    private const int RetryBootstrapReplayValidationFailureOpen = 7;
    private const int RetryBootstrapReplayValidationFailurePayload = 8;
    private const int RetryBootstrapReplayValidationFailureSourceEndpointMismatch = 9;
    private const int RetryBootstrapReplayValidationFailureTokenValidation = 10;
    private const int RetryBootstrapReplayValidationFailurePacketNumberReset = 11;
    private const int ReceiveBufferBytes = 4096;
    internal const int DesiredSocketReceiveBufferBytes = 4 * 1024 * 1024;
    private const int MaximumBufferedZeroRttDatagramsPerConnection = 2;
    private static readonly TimeSpan RetryBootstrapTokenLifetime = TimeSpan.FromMinutes(1);

    private readonly Socket socket;
    private readonly IPEndPoint boundSocketEndPoint;
    private readonly CancellationTokenSource shutdown = new();
    private readonly Channel<object> acceptQueue;
    private readonly List<SslApplicationProtocol> applicationProtocols;
    private readonly Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> connectionOptionsCallback;
    private readonly Func<IQuicDiagnosticsSink>? diagnosticsSinkFactory;
    private readonly Func<ReadOnlyMemory<byte>, SocketAddress, int>? datagramSender;
    private readonly IQuicDiagnosticsSink listenerDiagnosticsSink;
    private readonly Action<QuicTlsKeyLogSecret>? tlsKeyLogSecretObserver;
    private readonly Func<IQuicApplicationSendTurnPlanner>? applicationSendTurnPlannerFactory;
    private readonly QuicConnectionRuntimeEndpoint endpoint;
    private readonly QuicReceiveBufferPool receiveBufferPool = new(
        ReceiveBufferBytes,
        ownerName: nameof(QuicListenerHost),
        preallocateRingBuffers: true);
    private readonly QuicListenerZeroRttPreInitialBuffer zeroRttPreInitialBuffer = new(MaximumBufferedZeroRttDatagramsPerConnection);
    private readonly QuicServerResumptionTicketStore serverResumptionTicketStore = new();
    private readonly ConcurrentDictionary<QuicConnectionHandle, PendingConnectionState> connections = new();
    private readonly ConcurrentDictionary<string, int> versionNegotiationResponseCountsByRemoteAddress = new(StringComparer.Ordinal);
    private readonly int maximumVersionNegotiationResponsesPerRemoteAddress;
    private readonly bool retryBootstrapEnabled;
    private readonly QuicAddressValidationTokenProtector addressValidationTokenProtector;
    private readonly QuicAddressValidationTokenReplayCache addressValidationTokenReplayCache = new();
    private readonly uint flowLabelSeed = unchecked((uint)RandomNumberGenerator.GetInt32(1, int.MaxValue));
    private readonly bool windowsUdpSegmentationEnabled;

    private CancellationTokenSource? listenerCancellationSource;
    private CancellationTokenRegistration receiveLoopCancellationRegistration;
    private Task? runningTask;
    private int started;
    private int disposed;
    private int retryBootstrapIssued;
    private int retryBootstrapReplayValidated;
    private int retryBootstrapReplayAdmitted;
    private int retryBootstrapReplayValidationFailureCode;
    private int retryBootstrapObservedInitialPacketNumberSet;
    private int newTokenValidationAttempted;
    private int newTokenValidationSucceeded;
    private int newTokenValidationFailureCode;
    private ulong retryBootstrapLargestObservedInitialPacketNumber;
    private ReadOnlyMemory<byte>? retryBootstrapOriginalDestinationConnectionId;
    private ReadOnlyMemory<byte>? retryBootstrapSourceConnectionId;
    private ReadOnlyMemory<byte>? retryBootstrapToken;
    private QuicConnectionPathIdentity? retryBootstrapPathIdentity;
    private uint? retryBootstrapVersion;
    private string? retryBootstrapTokenHex;
    private string? retryBootstrapReplayTokenHex;
    private string? newTokenValidationTokenHex;

    public QuicListenerHost(
        IPEndPoint listenEndPoint,
        List<SslApplicationProtocol> applicationProtocols,
        Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> connectionOptionsCallback,
        int listenBacklog,
        bool retryBootstrapEnabled = false,
        Func<IQuicDiagnosticsSink>? diagnosticsSinkFactory = null,
        Action<QuicTlsKeyLogSecret>? tlsKeyLogSecretObserver = null,
        QuicAddressValidationTokenProtector? addressValidationTokenProtector = null,
        int maximumVersionNegotiationResponsesPerRemoteAddress = int.MaxValue,
        int runtimeShardCount = 1,
        Func<ReadOnlyMemory<byte>, SocketAddress, int>? datagramSender = null,
        Func<IQuicApplicationSendTurnPlanner>? applicationSendTurnPlannerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(listenEndPoint);
        ArgumentNullException.ThrowIfNull(applicationProtocols);
        ArgumentNullException.ThrowIfNull(connectionOptionsCallback);

        if (listenBacklog <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(listenBacklog));
        }

        if (maximumVersionNegotiationResponsesPerRemoteAddress < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumVersionNegotiationResponsesPerRemoteAddress));
        }

        if (runtimeShardCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(runtimeShardCount));
        }

        this.applicationProtocols = [.. applicationProtocols];
        this.connectionOptionsCallback = connectionOptionsCallback;
        this.retryBootstrapEnabled = retryBootstrapEnabled;
        this.diagnosticsSinkFactory = diagnosticsSinkFactory;
        this.datagramSender = datagramSender;
        this.applicationSendTurnPlannerFactory = applicationSendTurnPlannerFactory;
        listenerDiagnosticsSink = QuicDiagnostics.ResolveConnectionSink(diagnosticsSinkFactory?.Invoke());
        this.tlsKeyLogSecretObserver = tlsKeyLogSecretObserver;
        this.addressValidationTokenProtector = addressValidationTokenProtector ?? QuicAddressValidationTokenProtector.CreateEphemeral();
        this.maximumVersionNegotiationResponsesPerRemoteAddress = maximumVersionNegotiationResponsesPerRemoteAddress;
        endpoint = new QuicConnectionRuntimeEndpoint(runtimeShardCount, suppressHostedTimerEffectObjects: true);
        acceptQueue = Channel.CreateBounded<object>(new BoundedChannelOptions(listenBacklog)
        {
            SingleReader = false,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
            FullMode = BoundedChannelFullMode.Wait,
        });

        IPEndPoint boundEndPoint = new(listenEndPoint.Address, listenEndPoint.Port);
        socket = new Socket(boundEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (socket.AddressFamily == AddressFamily.InterNetworkV6 && boundEndPoint.Address.Equals(IPAddress.IPv6Any))
        {
            socket.DualMode = true;
        }
        QuicSocketFragmentationControl.TryEnableDontFragmentIfPossible(socket);
        QuicSocketPacketInformationControl.TryEnablePacketInformationIfPossible(socket);
        QuicSocketIcmpErrorControl.TryDisablePortUnreachableReporting(socket);

        socket.Bind(boundEndPoint);
        boundSocketEndPoint = (IPEndPoint)socket.LocalEndPoint!;
        windowsUdpSegmentationEnabled = datagramSender is null
            && QuicSocketUdpSegmentation.TryEnable(socket);
    }

    internal int RuntimeShardCount => endpoint.ShardCount;

    internal bool RetryBootstrapIssued => Volatile.Read(ref retryBootstrapIssued) != 0;

    internal bool RetryBootstrapReplayValidated => Volatile.Read(ref retryBootstrapReplayValidated) != 0;

    internal bool RetryBootstrapReplayAdmitted => Volatile.Read(ref retryBootstrapReplayAdmitted) != 0;

    internal int RetryBootstrapReplayValidationFailureCode => Volatile.Read(ref retryBootstrapReplayValidationFailureCode);

    internal bool NewTokenValidationAttempted => Volatile.Read(ref newTokenValidationAttempted) != 0;

    internal bool NewTokenValidationSucceeded => Volatile.Read(ref newTokenValidationSucceeded) != 0;

    internal int NewTokenValidationFailureCode => Volatile.Read(ref newTokenValidationFailureCode);

    internal string? RetryBootstrapTokenHex => retryBootstrapTokenHex;

    internal string? RetryBootstrapReplayTokenHex => retryBootstrapReplayTokenHex;

    internal string? NewTokenValidationTokenHex => newTokenValidationTokenHex;

    internal Socket Socket => socket;

    private static void TryIncreaseSocketReceiveBuffer(Socket targetSocket)
    {
        try
        {
            if (targetSocket.ReceiveBufferSize < DesiredSocketReceiveBufferBytes)
            {
                targetSocket.ReceiveBufferSize = DesiredSocketReceiveBufferBytes;
            }
        }
        catch (SocketException)
        {
            // The platform default remains functional when an OS policy caps or rejects the request.
        }
    }

    internal QuicReceiveBufferPoolSnapshot ReceiveBufferPoolSnapshot => receiveBufferPool.Snapshot;

    internal QuicConnectionRuntimeEndpoint Endpoint => endpoint;

    internal Task? RunningTask => runningTask;

    internal bool TryGetFirstPendingConnection(out QuicConnection connection)
    {
        using var enumerator = connections.Values.GetEnumerator();
        if (enumerator.MoveNext())
        {
            connection = enumerator.Current.Connection;
            return true;
        }

        connection = default!;
        return false;
    }

    internal bool TryGetFirstPendingHandshakeDatagram(out ReadOnlyMemory<byte> datagram)
    {
        foreach (PendingConnectionState state in connections.Values)
        {
            foreach (QuicConnectionTransitionResult transition in state.TransitionHistory)
            {
                if (transition.EventKind != QuicConnectionEventKind.PacketReceived)
                {
                    continue;
                }

                for (int index = 0; index < transition.EffectCount; index++)
                {
                    QuicConnectionEffect effect = transition.GetEffect(index);
                    if (effect is not QuicConnectionSendDatagramEffect sendEffect)
                    {
                        continue;
                    }

                    if (QuicPacketParser.TryGetPacketNumberSpace(sendEffect.Datagram.Span, out QuicPacketNumberSpace packetNumberSpace)
                        && packetNumberSpace == QuicPacketNumberSpace.Handshake)
                    {
                        datagram = sendEffect.Datagram;
                        return true;
                    }
                }
            }
        }

        datagram = ReadOnlyMemory<byte>.Empty;
        return false;
    }

    internal string DescribeFirstPendingConnectionTransition()
    {
        QuicConnectionTransitionResult[] firstTransition = connections.Values
            .SelectMany(static state => state.TransitionHistory)
            .Take(1)
            .ToArray();

        if (firstTransition.Length > 0)
        {
            QuicConnectionTransitionResult transition = firstTransition[0];
            string[] effectNames = new string[transition.EffectCount];
            for (int index = 0; index < effectNames.Length; index++)
            {
                effectNames[index] = transition.GetEffect(index).GetType().Name;
            }

            string effectSummary = string.Join(
                ", ",
                effectNames);

            return $"ListenerPacketTransition=Prev:{transition.PreviousPhase}; Curr:{transition.CurrentPhase}; StateChanged:{transition.StateChanged}; Effects:[{effectSummary}]";
        }

        return connections.IsEmpty
            ? "ListenerTransitions=<no pending connection>"
            : "ListenerTransitions=<no packet transition observed>";
    }

    public Task RunAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (Interlocked.CompareExchange(ref started, 1, 0) != 0)
        {
            throw new InvalidOperationException("The listener host can only be started once.");
        }

        listenerCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);
        CancellationToken hostCancellation = listenerCancellationSource.Token;
        receiveLoopCancellationRegistration = hostCancellation.UnsafeRegister(
            static state => ((QuicListenerHost)state!).WakeReceiveLoop(),
            this);

        Task endpointTask = endpoint.RunAsync(
            ObserveTransition,
            ObserveEffect,
            hostCancellation,
            ObserveSendDatagram,
            windowsUdpSegmentationEnabled ? ObserveSendDatagrams : null);

        Task receiveTask = ReceiveLoopAsync(hostCancellation);
        ObserveBackgroundTaskFault(endpointTask);
        ObserveBackgroundTaskFault(receiveTask);
        runningTask = Task.WhenAll(endpointTask, receiveTask);
        return runningTask;
    }

    private void ObserveBackgroundTaskFault(Task task)
    {
        _ = task.ContinueWith(
            static (faultedTask, state) =>
            {
                QuicListenerHost host = (QuicListenerHost)state!;
                Exception exception = faultedTask.Exception?.GetBaseException()
                    ?? new InvalidOperationException("A QUIC listener background task failed without an exception.");
                host.acceptQueue.Writer.TryComplete(exception);
                host.shutdown.Cancel();
            },
            this,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    public async ValueTask<QuicConnection> AcceptConnectionAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        using CancellationTokenSource acceptCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);

        try
        {
            object item = await acceptQueue.Reader.ReadAsync(acceptCancellationSource.Token).ConfigureAwait(false);
            return UnwrapQueuedItem(item);
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new ObjectDisposedException(nameof(QuicListenerHost));
        }
        catch (ChannelClosedException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await shutdown.CancelAsync().ConfigureAwait(false);
        CancellationTokenSource? cancellationSource = Interlocked.Exchange(ref listenerCancellationSource, null);
        if (cancellationSource is not null)
        {
            await cancellationSource.CancelAsync().ConfigureAwait(false);
        }

        acceptQueue.Writer.TryComplete(ExceptionDispatchInfo.SetCurrentStackTrace(new ObjectDisposedException(nameof(QuicListenerHost))));

        try
        {
            await endpoint.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
            // Best-effort shutdown only.
        }

        Task? task = runningTask;
        if (task is not null)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
            {
                // Expected during shutdown.
            }
        }

        foreach (PendingConnectionState state in connections.Values)
        {
            try
            {
                await state.Connection.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // Best-effort cleanup only.
            }
        }

        while (acceptQueue.Reader.TryRead(out object? item))
        {
            if (item is QuicConnection connection)
            {
                try
                {
                    await connection.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                    // Best-effort cleanup only.
                }
            }
        }

        versionNegotiationResponseCountsByRemoteAddress.Clear();
        serverResumptionTicketStore.Clear();
        await receiveLoopCancellationRegistration.DisposeAsync().ConfigureAwait(false);
        try
        {
            socket.Dispose();
        }
        catch
        {
            // Best-effort shutdown only.
        }

        cancellationSource?.Dispose();
        receiveBufferPool.Dispose();
        shutdown.Dispose();
    }

    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        QuicReusableReceiveEndPoint remoteEndPoint = new(socket.AddressFamily);
        QuicSocketPacketInformationControl.LocalEndPointCache localEndPointCache = new();
        bool requiresPacketInformation =
            QuicSocketPacketInformationControl.RequiresPacketInformation(boundSocketEndPoint);

        while (!cancellationToken.IsCancellationRequested)
        {
            QuicReceiveBufferLease datagramLease = receiveBufferPool.Rent();
            try
            {
                SocketReceiveMessageFromResult receiveMessageResult = default;
                EndPoint receivedRemoteEndPoint;
                int receivedBytes;
                try
                {
                    remoteEndPoint.PrepareForReceive();
                    if (requiresPacketInformation)
                    {
                        receiveMessageResult = await socket.ReceiveMessageFromAsync(
                            datagramLease.Memory,
                            SocketFlags.None,
                            remoteEndPoint,
                            CancellationToken.None).ConfigureAwait(false);
                        receivedBytes = receiveMessageResult.ReceivedBytes;
                        receivedRemoteEndPoint = receiveMessageResult.RemoteEndPoint;
                    }
                    else
                    {
                        receivedBytes = await socket.ReceiveFromAsync(
                            datagramLease.Memory,
                            SocketFlags.None,
                            remoteEndPoint.ReceiveAddress,
                            CancellationToken.None).ConfigureAwait(false);
                        receivedRemoteEndPoint = remoteEndPoint.ResolveReceivedEndPoint();
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException) when (shutdown.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.ConnectionRefused)
                {
                    // Windows can surface ICMP errors from a prior UDP peer on the shared listener socket.
                    // Treat them as per-datagram noise so one closed peer does not stop unrelated connections.
                    QuicMetrics.RecordUdpError(QuicTlsRole.Server, "receive", ex.SocketErrorCode);
                    continue;
                }

                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref disposed) != 0)
                {
                    break;
                }

                if (receivedBytes <= 0)
                {
                    continue;
                }

                QuicMetrics.RecordDatagramReceived(QuicTlsRole.Server, receivedBytes);
                IPEndPoint receivedFrom = (IPEndPoint)receivedRemoteEndPoint;
                QuicConnectionPathIdentity pathIdentity;
                try
                {
                    IPEndPoint localEndPoint = requiresPacketInformation
                        ? localEndPointCache.Resolve(
                            boundSocketEndPoint,
                            receiveMessageResult.PacketInformation.Address)
                        : boundSocketEndPoint;
                    pathIdentity = CreatePathIdentity(receivedFrom, localEndPoint);
                }
                catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
                {
                    break;
                }

                EmitSocketDatagramReceived(pathIdentity, receivedBytes);
                byte[] datagramBuffer = datagramLease.Buffer;
                ReadOnlyMemory<byte> datagram = datagramBuffer.AsMemory(0, receivedBytes);
                QuicEcnCounts? ecnCounts = requiresPacketInformation
                    && QuicSocketEcnControl.TryGetReceivedEcnCounts(
                        receiveMessageResult,
                        out QuicEcnCounts receivedEcnCounts)
                    ? receivedEcnCounts
                    : null;
                QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(
                    datagram,
                    pathIdentity,
                    ecnCounts,
                    ownedDatagramBuffer: datagramBuffer,
                    ownedDatagramBufferOwnership: datagramLease.Ownership);
                EmitListenerIngressClassified(pathIdentity, ingressResult);
                if (ingressResult.Disposition == QuicConnectionIngressDisposition.RoutedToConnection)
                {
                    datagramLease.TransferToRuntime();
                    continue;
                }

                if (ingressResult.Disposition == QuicConnectionIngressDisposition.EndpointHandling
                    || ingressResult.Disposition == QuicConnectionIngressDisposition.Dropped)
                {
                    if (ingressResult.Disposition == QuicConnectionIngressDisposition.Dropped)
                    {
                        QuicMetrics.RecordPacketDropped(QuicTlsRole.Server);
                    }

                    continue;
                }

                if (TrySendStatelessResetResponse(datagram, pathIdentity))
                {
                    continue;
                }

                QuicListenerPreAcceptanceDatagramAction action =
                    QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                        datagram.Span,
                        ListenerSupportedVersions,
                        retryBootstrapEnabled,
                        maximumBufferedZeroRttDatagramsPerConnection: MaximumBufferedZeroRttDatagramsPerConnection);
                EmitListenerPreAcceptanceClassified(pathIdentity, action);

                if (action == QuicListenerPreAcceptanceDatagramAction.SendVersionNegotiation)
                {
                    _ = TrySendVersionNegotiationResponse(datagram.Span, pathIdentity);
                    continue;
                }

                if (action == QuicListenerPreAcceptanceDatagramAction.SendProtocolViolationClose)
                {
                    TrySendProtocolViolationCloseResponse(pathIdentity);
                    continue;
                }

                if (action == QuicListenerPreAcceptanceDatagramAction.BufferZeroRtt
                    && TryBufferZeroRttPreInitialDatagram(datagram, pathIdentity))
                {
                    continue;
                }

                if (action == QuicListenerPreAcceptanceDatagramAction.AdmitInitial
                    && TryPrepareInitialAdmissionFields(
                        datagram,
                        pathIdentity,
                        out ReadOnlyMemory<byte> initialPacket,
                        out uint initialVersion,
                        out ReadOnlyMemory<byte> initialDestinationConnectionId,
                        out ReadOnlyMemory<byte> clientSourceConnectionId,
                        out ReadOnlyMemory<byte> initialToken))
                {
                    try
                    {
                        if (await TryAdmitIncomingInitialConnectionAsync(
                            initialPacket,
                            pathIdentity,
                            initialVersion,
                            initialDestinationConnectionId,
                            clientSourceConnectionId,
                            initialToken,
                            cancellationToken).ConfigureAwait(false))
                        {
                            ingressResult = endpoint.ReceiveDatagram(
                                datagram,
                                pathIdentity,
                                ownedDatagramBuffer: datagramBuffer,
                                ownedDatagramBufferOwnership: datagramLease.Ownership);
                            if (ingressResult.Disposition == QuicConnectionIngressDisposition.RoutedToConnection)
                            {
                                datagramLease.TransferToRuntime();
                            }

                            FlushBufferedZeroRttDatagrams(initialDestinationConnectionId.Span);
                        }
                    }
                    catch (Exception ex)
                    {
                        EmitListenerInitialAdmissionResult(
                            pathIdentity,
                            "admit-initial-connection",
                            succeeded: false,
                            FormatAdmissionExceptionReason(ex));
                        // Admission failures remain local to the listener shell.
                    }
                }

                if (action == QuicListenerPreAcceptanceDatagramAction.IssueRetryBootstrap
                    && TryIssueRetryBootstrapResponseFromZeroRttDatagram(datagram, pathIdentity))
                {
                    continue;
                }
            }
            finally
            {
                datagramLease.Dispose();
            }
        }
    }

    private void EmitSocketDatagramReceived(QuicConnectionPathIdentity pathIdentity, int datagramLength)
    {
        if (!listenerDiagnosticsSink.IsEnabled)
        {
            return;
        }

        listenerDiagnosticsSink.Emit(QuicDiagnostics.SocketDatagramReceived(pathIdentity, datagramLength));
    }

    private void EmitListenerIngressClassified(
        QuicConnectionPathIdentity pathIdentity,
        QuicConnectionIngressResult ingressResult)
    {
        if (!listenerDiagnosticsSink.IsEnabled)
        {
            return;
        }

        listenerDiagnosticsSink.Emit(QuicDiagnostics.ListenerIngressClassified(pathIdentity, ingressResult));
    }

    private void EmitListenerPreAcceptanceClassified(
        QuicConnectionPathIdentity pathIdentity,
        QuicListenerPreAcceptanceDatagramAction action)
    {
        if (!listenerDiagnosticsSink.IsEnabled)
        {
            return;
        }

        listenerDiagnosticsSink.Emit(QuicDiagnostics.ListenerPreAcceptanceClassified(pathIdentity, action));
    }

    private void EmitListenerInitialAdmissionResult(
        QuicConnectionPathIdentity pathIdentity,
        string stage,
        bool succeeded,
        string reason)
    {
        if (!listenerDiagnosticsSink.IsEnabled)
        {
            return;
        }

        listenerDiagnosticsSink.Emit(QuicDiagnostics.ListenerInitialAdmissionResult(pathIdentity, stage, succeeded, reason));
    }

    private bool TryBufferZeroRttPreInitialDatagram(ReadOnlyMemory<byte> datagram, QuicConnectionPathIdentity pathIdentity)
    {
        if (!QuicPacketParser.TryParseLongHeader(datagram.Span, out QuicLongHeaderPacket zeroRttHeader))
        {
            return false;
        }

        return zeroRttPreInitialBuffer.TryBuffer(
            zeroRttHeader.DestinationConnectionId,
            datagram,
            pathIdentity);
    }

    private bool TryPrepareInitialAdmissionFields(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        out ReadOnlyMemory<byte> initialPacket,
        out uint initialVersion,
        out ReadOnlyMemory<byte> initialDestinationConnectionId,
        out ReadOnlyMemory<byte> clientSourceConnectionId,
        out ReadOnlyMemory<byte> initialToken)
    {
        initialPacket = default;
        initialVersion = default;
        initialDestinationConnectionId = default;
        clientSourceConnectionId = default;
        initialToken = default;

        if (!QuicListenerPreAcceptanceIngressPolicy.TrySliceFirstPacketForAdmission(datagram, out initialPacket))
        {
            EmitListenerInitialAdmissionResult(
                pathIdentity,
                "slice-first-packet",
                succeeded: false,
                "packet-length-parse-failed");
            return false;
        }

        if (!TryReadInitialAdmissionFields(
            initialPacket,
            out initialVersion,
            out initialDestinationConnectionId,
            out clientSourceConnectionId,
            out initialToken))
        {
            EmitListenerInitialAdmissionResult(
                pathIdentity,
                "read-initial-admission-fields",
                succeeded: false,
                "initial-header-or-token-parse-failed");
            return false;
        }

        EmitListenerInitialAdmissionResult(
            pathIdentity,
            "read-initial-admission-fields",
            succeeded: true,
            "initial-fields-ready");
        return true;
    }

    private static bool TryReadInitialAdmissionFields(
        ReadOnlyMemory<byte> datagram,
        out uint initialVersion,
        out ReadOnlyMemory<byte> initialDestinationConnectionId,
        out ReadOnlyMemory<byte> clientSourceConnectionId,
        out ReadOnlyMemory<byte> initialToken)
    {
        initialVersion = default;
        initialDestinationConnectionId = default;
        clientSourceConnectionId = default;
        initialToken = default;

        if (!QuicPacketParsing.TryParseLongHeaderMemoryFields(
                datagram,
                out byte headerControlBits,
                out initialVersion,
                out initialDestinationConnectionId,
                out clientSourceConnectionId,
                out ReadOnlyMemory<byte> versionSpecificData)
            || !QuicVersionNegotiation.IsSupportedTransportVersion(initialVersion)
            || !QuicVersionNegotiation.IsLongHeaderPacketType(
                initialVersion,
                (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift),
                QuicLongPacketType.Initial)
            || !TryParseInitialToken(versionSpecificData, out initialToken))
        {
            return false;
        }

        return true;
    }

    private void FlushBufferedZeroRttDatagrams(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        foreach (QuicListenerBufferedZeroRttDatagram bufferedDatagram in zeroRttPreInitialBuffer.Drain(initialDestinationConnectionId))
        {
            _ = endpoint.ReceiveDatagram(bufferedDatagram.Datagram, bufferedDatagram.PathIdentity);
        }
    }

    private bool TrySendStatelessResetResponse(ReadOnlyMemory<byte> triggeringDatagram, QuicConnectionPathIdentity pathIdentity)
    {
        QuicConnectionStatelessResetEmissionResult reset = endpoint.TryCreateStatelessResetDatagramForPacket(
            triggeringDatagram,
            pathIdentity,
            hasLoopPreventionState: true);

        if (!reset.Emitted)
        {
            return false;
        }

        try
        {
            EndPoint remoteEndPoint = CreateRemoteEndPoint(pathIdentity);
            int bytesSent = socket.SendTo(reset.Datagram.Span, SocketFlags.None, remoteEndPoint);
            return bytesSent == reset.Datagram.Length;
        }
        catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException) when (shutdown.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException ex)
        {
            QuicMetrics.RecordUdpError(QuicTlsRole.Server, "send", ex.SocketErrorCode);
            return false;
        }
    }

    private void ObserveTransition(QuicConnectionHandle handle, int shardIndex, QuicConnectionTransitionResult transition)
    {
        _ = shardIndex;

        if (!connections.TryGetValue(handle, out PendingConnectionState? state))
        {
            return;
        }

        if (state.IsPending)
        {
            state.TransitionHistory.Enqueue(transition);
        }

        if (state.Runtime.TerminalState is QuicConnectionTerminalState terminalState
            && state.TryMarkFailed())
        {
            connections.TryRemove(handle, out _);
            _ = QueueConnectionFailureAsync(state.Connection, MapTerminalState(terminalState));
            return;
        }

        if (ShouldQueueAcceptedConnection(transition, state.Runtime)
            && state.TryMarkAccepted())
        {
            state.Connection.SetResumptionOutcome(QuicConnection.MapResumptionOutcome(state.Runtime.ResumptionAttemptDisposition));
            _ = QueueAcceptedConnectionAsync(state.Connection);
        }
    }

    internal static bool ShouldQueueAcceptedConnection(
        QuicConnectionTransitionResult transition,
        QuicConnectionRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        return (transition.CurrentPhase == QuicConnectionPhase.Active
                || runtime.Phase == QuicConnectionPhase.Active)
            && runtime.PeerHandshakeTranscriptCompleted;
    }

    private void ObserveEffect(QuicConnectionHandle handle, int shardIndex, QuicConnectionEffect effect)
    {
        _ = handle;
        _ = shardIndex;

        if (Volatile.Read(ref disposed) != 0 || shutdown.IsCancellationRequested)
        {
            return;
        }

        if (effect is QuicConnectionSendDatagramEffect sendDatagramEffect)
        {
            SendDatagram(handle, sendDatagramEffect);
        }
    }

    private void ObserveSendDatagram(
        QuicConnectionHandle handle,
        int shardIndex,
        QuicConnectionSendDatagramUpdate sendDatagram)
    {
        _ = shardIndex;
        SendDatagram(handle, sendDatagram);
    }

    private void ObserveSendDatagrams(
        QuicConnectionHandle handle,
        int shardIndex,
        ReadOnlySpan<QuicConnectionSendDatagramUpdate> sendDatagrams)
    {
        _ = shardIndex;
        if (!connections.TryGetValue(handle, out PendingConnectionState? state))
        {
            return;
        }

        int index = 0;
        while (index < sendDatagrams.Length)
        {
            int batchCount = GetSegmentableRunLength(sendDatagrams[index..]);
            if (batchCount >= QuicSocketUdpSegmentation.MinimumSegmentsPerSend)
            {
                TrySendSegmentedDatagrams(state, sendDatagrams.Slice(index, batchCount));
                index += batchCount;
                continue;
            }

            QuicConnectionSendDatagramUpdate sendDatagram = sendDatagrams[index];
            SendDatagram(
                state.FlowLabelSeed,
                sendDatagram,
                state.GetRemoteSocketAddress(sendDatagram.PathIdentity));
            index++;
        }
    }

    private static int GetSegmentableRunLength(
        ReadOnlySpan<QuicConnectionSendDatagramUpdate> sendDatagrams)
    {
        QuicConnectionSendDatagramUpdate first = sendDatagrams[0];
        if (first.Datagram.Length != QuicSocketUdpSegmentation.SegmentSize
            || !MemoryMarshal.TryGetArray(first.Datagram, out ArraySegment<byte> firstSegment)
            || firstSegment.Array is null)
        {
            return 0;
        }

        int limit = Math.Min(sendDatagrams.Length, QuicSocketUdpSegmentation.MaximumSegmentsPerSend);
        int count = 1;
        while (count < limit)
        {
            QuicConnectionSendDatagramUpdate current = sendDatagrams[count];
            if (current.Datagram.Length != QuicSocketUdpSegmentation.SegmentSize
                || current.PathIdentity != first.PathIdentity
                || current.EcnMarking != first.EcnMarking
                || !MemoryMarshal.TryGetArray(current.Datagram, out ArraySegment<byte> currentSegment)
                || !ReferenceEquals(currentSegment.Array, firstSegment.Array)
                || currentSegment.Offset != firstSegment.Offset + (count * QuicSocketUdpSegmentation.SegmentSize))
            {
                break;
            }

            count++;
        }

        return count;
    }

    private void TrySendSegmentedDatagrams(
        PendingConnectionState state,
        ReadOnlySpan<QuicConnectionSendDatagramUpdate> sendDatagrams)
    {
        try
        {
            QuicConnectionSendDatagramUpdate first = sendDatagrams[0];
            if (!MemoryMarshal.TryGetArray(first.Datagram, out ArraySegment<byte> firstSegment)
                || firstSegment.Array is null)
            {
                throw new InvalidOperationException("The segmented send lost its contiguous array owner.");
            }

            _ = QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, first.EcnMarking);
            SocketAddress destination = state.GetRemoteSocketAddress(first.PathIdentity);
            int length = checked(sendDatagrams.Length * QuicSocketUdpSegmentation.SegmentSize);
            _ = QuicSocketUdpSegmentation.Send(
                socket,
                firstSegment.Array.AsSpan(firstSegment.Offset, length),
                sendDatagrams.Length,
                destination);
            foreach (QuicConnectionSendDatagramUpdate sendDatagram in sendDatagrams)
            {
                QuicMetrics.RecordDatagramSent(QuicTlsRole.Server, sendDatagram.Datagram.Length);
            }
        }
        catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
        {
            // Expected during listener shutdown.
        }
        catch (SocketException) when (shutdown.IsCancellationRequested)
        {
            // Expected during listener shutdown.
        }
        catch (SocketException ex) when (IsPeerPathSendSocketError(ex.SocketErrorCode)
            || IsTransientSendSocketError(ex.SocketErrorCode))
        {
            RecordUdpSendFailure(ex);
            for (int index = 1; index < sendDatagrams.Length; index++)
            {
                QuicMetrics.RecordPacketDropped(QuicTlsRole.Server);
            }
        }
        catch (IOException)
        {
            foreach (QuicConnectionSendDatagramUpdate _ in sendDatagrams)
            {
                QuicMetrics.RecordPacketDropped(QuicTlsRole.Server);
            }
        }
    }

    private void WakeReceiveLoop()
    {
        if (QuicSocketReceiveLoopWakeup.TryWake(socket))
        {
            return;
        }

        try
        {
            socket.Dispose();
        }
        catch
        {
            // Falling back to socket disposal only needs to unblock the receive loop.
        }
    }

    private void SendDatagram(QuicConnectionHandle handle, QuicConnectionSendDatagramEffect sendDatagramEffect)
        => SendDatagram(handle, new QuicConnectionSendDatagramUpdate(
            sendDatagramEffect.PathIdentity,
            sendDatagramEffect.Datagram,
            sendDatagramEffect.EcnMarking));

    private void SendDatagram(QuicConnectionHandle handle, QuicConnectionSendDatagramUpdate sendDatagram)
    {
        if (!connections.TryGetValue(handle, out PendingConnectionState? state))
        {
            return;
        }

        SendDatagram(state.FlowLabelSeed, sendDatagram, state.GetRemoteSocketAddress(sendDatagram.PathIdentity));
    }

    internal void SendDatagram(QuicConnectionSendDatagramEffect sendDatagramEffect)
    {
        SendDatagram(flowLabelSeed, sendDatagramEffect);
    }

    private void SendDatagram(
        uint flowLabelSeed,
        QuicConnectionSendDatagramEffect sendDatagramEffect,
        SocketAddress? remoteSocketAddress = null)
        => SendDatagram(
            flowLabelSeed,
            new QuicConnectionSendDatagramUpdate(
                sendDatagramEffect.PathIdentity,
                sendDatagramEffect.Datagram,
                sendDatagramEffect.EcnMarking),
            remoteSocketAddress);

    private void SendDatagram(
        uint flowLabelSeed,
        QuicConnectionSendDatagramUpdate sendDatagram,
        SocketAddress? remoteSocketAddress = null)
    {
        try
        {
            _ = QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, sendDatagram.EcnMarking);
            int bytesSent;
            if (OperatingSystem.IsLinux()
                && TryResolvePacketInformationSourceAddress(
                boundSocketEndPoint,
                socket.AddressFamily,
                sendDatagram.PathIdentity,
                out IPAddress sourceAddress)
                && (socket.AddressFamily == AddressFamily.InterNetworkV6
                    || !sourceAddress.Equals(boundSocketEndPoint.Address)))
            {
                uint flowLabel = sourceAddress.AddressFamily == AddressFamily.InterNetworkV6
                    ? QuicSocketPacketInformationSender.CreateIpv6FlowLabel(flowLabelSeed, sendDatagram.PathIdentity)
                    : 0;

                if (!QuicSocketPacketInformationSender.TrySendTo(
                    socket,
                    sendDatagram.Datagram.Span,
                    CreateRemoteEndPoint(sendDatagram.PathIdentity),
                    sourceAddress,
                    flowLabel,
                    out bytesSent))
                {
                    return;
                }
            }
            else
            {
                SocketAddress destination = remoteSocketAddress ?? CreateRemoteSocketAddress(sendDatagram.PathIdentity);
                bytesSent = datagramSender is null
                    ? socket.SendTo(sendDatagram.Datagram.Span, SocketFlags.None, destination)
                    : datagramSender(sendDatagram.Datagram, destination);
            }

            if (bytesSent != sendDatagram.Datagram.Length)
            {
                QuicMetrics.RecordPacketDropped(QuicTlsRole.Server);
                return;
            }

            QuicMetrics.RecordDatagramSent(QuicTlsRole.Server, bytesSent);

        }
        catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
        {
            // Expected during shutdown.
        }
        catch (SocketException) when (shutdown.IsCancellationRequested)
        {
            // Expected during shutdown.
        }
        catch (SocketException ex) when (IsPeerPathSendSocketError(ex.SocketErrorCode))
        {
            // A shared UDP listener cannot reliably map these ICMP errors back to a live managed
            // connection. Keep the endpoint alive so unrelated sequential accepts can finish.
            RecordUdpSendFailure(ex);
        }
        catch (SocketException ex) when (IsTransientSendSocketError(ex.SocketErrorCode))
        {
            // The runtime already tracks this packet for recovery. Treat transient local UDP
            // pressure as a dropped datagram so PTO can retry without terminating the shard.
            RecordUdpSendFailure(ex);
        }
    }

    private void RecordUdpSendFailure(SocketException exception)
    {
        QuicMetrics.RecordUdpError(QuicTlsRole.Server, "send", exception.SocketErrorCode);
        QuicMetrics.RecordPacketDropped(QuicTlsRole.Server);

        if (listenerDiagnosticsSink.IsEnabled)
        {
            listenerDiagnosticsSink.Emit(QuicDiagnostics.UdpSendError(
                exception.SocketErrorCode.ToString(),
                exception.ErrorCode));
        }
    }

    internal static bool IsTransientSendSocketError(SocketError socketError)
        => socketError is SocketError.Interrupted
            or SocketError.WouldBlock
            or SocketError.TryAgain
            or SocketError.NoBufferSpaceAvailable;

    internal static bool IsPeerPathSendSocketError(SocketError socketError)
        => socketError is SocketError.ConnectionReset
            or SocketError.ConnectionAborted
            or SocketError.ConnectionRefused
            or SocketError.HostUnreachable
            or SocketError.NetworkUnreachable
            or SocketError.NetworkReset
            or SocketError.TimedOut;

    private static bool TryResolvePacketInformationSourceAddress(
        IPEndPoint socketLocalEndPoint,
        AddressFamily socketAddressFamily,
        QuicConnectionPathIdentity pathIdentity,
        out IPAddress sourceAddress)
    {
        ArgumentNullException.ThrowIfNull(socketLocalEndPoint);

        sourceAddress = IPAddress.None;
        if (pathIdentity.LocalAddress is not string localAddress
            || pathIdentity.LocalPort != socketLocalEndPoint.Port
            || !IPAddress.TryParse(localAddress, out IPAddress? parsedAddress)
            || IsWildcardAddress(parsedAddress))
        {
            return false;
        }

        if (socketAddressFamily == AddressFamily.InterNetworkV6
            && parsedAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            sourceAddress = parsedAddress;
            return true;
        }

        if (socketAddressFamily == AddressFamily.InterNetwork
            && parsedAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            sourceAddress = parsedAddress;
            return true;
        }

        return false;
    }

    private static bool IsWildcardAddress(IPAddress address)
    {
        return address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
    }

    private bool TrySendVersionNegotiationResponse(ReadOnlySpan<byte> datagram, QuicConnectionPathIdentity pathIdentity)
    {
        if (!QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket longHeader)
            || !QuicVersionNegotiation.ShouldSendVersionNegotiation(
                longHeader.Version,
                datagram.Length,
                ListenerSupportedVersions)
            || !TryReserveVersionNegotiationResponse(pathIdentity.RemoteAddress))
        {
            return false;
        }

        byte[] responseDatagram = QuicBufferPool.RentBytes(
            datagram.Length,
            QuicBufferPoolOwner.ListenerResponse);
        try
        {
            if (!QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
                    longHeader.Version,
                    longHeader.DestinationConnectionId,
                    longHeader.SourceConnectionId,
                    ListenerSupportedVersions,
                    responseDatagram,
                    out int bytesWritten))
            {
                return false;
            }

            EndPoint remoteEndPoint = CreateRemoteEndPoint(pathIdentity);
            int bytesSent = socket.SendTo(responseDatagram.AsSpan(0, bytesWritten), SocketFlags.None, remoteEndPoint);
            if (bytesSent != bytesWritten)
            {
                return false;
            }

            IQuicDiagnosticsSink? diagnosticsSink = diagnosticsSinkFactory?.Invoke();
            diagnosticsSink?.Emit(QuicDiagnostics.VersionNegotiationSent(pathIdentity, responseDatagram.AsSpan(0, bytesWritten)));
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            QuicBufferPool.ReturnBytes(responseDatagram);
        }
    }

    private bool TryReserveVersionNegotiationResponse(string remoteAddress)
    {
        if (maximumVersionNegotiationResponsesPerRemoteAddress == int.MaxValue)
        {
            return true;
        }

        if (maximumVersionNegotiationResponsesPerRemoteAddress == 0)
        {
            return false;
        }

        while (true)
        {
            if (!versionNegotiationResponseCountsByRemoteAddress.TryGetValue(remoteAddress, out int currentCount))
            {
                if (versionNegotiationResponseCountsByRemoteAddress.TryAdd(remoteAddress, 1))
                {
                    return true;
                }

                continue;
            }

            if (currentCount >= maximumVersionNegotiationResponsesPerRemoteAddress)
            {
                return false;
            }

            if (versionNegotiationResponseCountsByRemoteAddress.TryUpdate(remoteAddress, currentCount + 1, currentCount))
            {
                return true;
            }
        }
    }

    private static IPEndPoint CreateRemoteEndPoint(QuicConnectionPathIdentity pathIdentity)
    {
        return new IPEndPoint(
            IPAddress.Parse(pathIdentity.RemoteAddress),
            pathIdentity.RemotePort ?? throw new InvalidOperationException("The listener connection path is missing a remote port."));
    }

    private static SocketAddress CreateRemoteSocketAddress(QuicConnectionPathIdentity pathIdentity)
    {
        return CreateRemoteEndPoint(pathIdentity).Serialize();
    }

    private void TrySendProtocolViolationCloseResponse(QuicConnectionPathIdentity pathIdentity)
    {
        byte[] closeDatagram = QuicBufferPool.RentBytes(
            32,
            QuicBufferPoolOwner.ListenerResponse);
        try
        {
            if (!QuicFrameCodec.TryFormatConnectionCloseFrame(
                new QuicConnectionCloseFrame(
                    QuicTransportErrorCode.ProtocolViolation,
                    triggeringFrameType: 0,
                    []),
                closeDatagram,
                out int bytesWritten))
            {
                return;
            }

            SendDatagram(new QuicConnectionSendDatagramEffect(
                pathIdentity,
                closeDatagram.AsMemory(0, bytesWritten)));
        }
        finally
        {
            QuicBufferPool.ReturnBytes(closeDatagram);
        }
    }

    private bool TrySendConnectionRefusedCloseResponse(
        QuicConnectionPathIdentity pathIdentity,
        uint initialVersion,
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> clientSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId)
    {
        return TrySendInitialCloseResponse(
            pathIdentity,
            initialVersion,
            initialDestinationConnectionId,
            clientSourceConnectionId,
            serverSourceConnectionId,
            QuicTransportErrorCode.ConnectionRefused);
    }

    private bool TrySendInitialCloseResponse(
        QuicConnectionPathIdentity pathIdentity,
        uint initialVersion,
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> clientSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId,
        QuicTransportErrorCode errorCode)
    {
        if (!QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            initialVersion,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection))
        {
            return false;
        }

        QuicHandshakeFlowCoordinator closePacketCoordinator = new(
            initialDestinationConnectionId.ToArray(),
            serverSourceConnectionId.ToArray());
        if (!closePacketCoordinator.TrySetHandshakeDestinationConnectionId(clientSourceConnectionId))
        {
            return false;
        }

        Span<byte> closePayload = stackalloc byte[32];
        if (!QuicFrameCodec.TryFormatConnectionCloseFrame(
            new QuicConnectionCloseFrame(errorCode, triggeringFrameType: 0, []),
            closePayload,
            out int closePayloadLength))
        {
            return false;
        }

        if (!closePacketCoordinator.TryBuildProtectedInitialControlPacketForHandshakeDestination(
            closePayload[..closePayloadLength],
            initialProtection,
            out _,
            out byte[] closeDatagram))
        {
            return false;
        }

        SendDatagram(new QuicConnectionSendDatagramEffect(pathIdentity, closeDatagram));
        return true;
    }

    private async ValueTask<bool> TryAdmitIncomingInitialConnectionAsync(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        uint initialVersion,
        ReadOnlyMemory<byte> initialDestinationConnectionId,
        ReadOnlyMemory<byte> clientSourceConnectionId,
        ReadOnlyMemory<byte> initialToken,
        CancellationToken cancellationToken)
    {
        bool isRetryBootstrapReplayCandidate =
            retryBootstrapEnabled
            && retryBootstrapSourceConnectionId is not null
            && initialDestinationConnectionId.Span.SequenceEqual(retryBootstrapSourceConnectionId.Value.Span);
        bool newTokenValidated = false;

        QuicServerConnectionOptions selectedOptions = new();
        QuicConnectionRuntime? runtime = null;
        QuicConnection? connection = null;
        QuicConnectionHandle handle = default;
        bool admitted = false;

        try
        {
            bool Fail(string stage, string reason)
            {
                EmitListenerInitialAdmissionResult(pathIdentity, stage, succeeded: false, reason);
                return false;
            }

            if (!QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Server,
                initialVersion,
                initialDestinationConnectionId.Span,
                out QuicInitialPacketProtection initialProtection))
            {
                return Fail("create-initial-packet-protection", "unsupported-version-or-protection-create-failed");
            }

            QuicHandshakeFlowCoordinator initialPacketCoordinator = new();
            if (!initialPacketCoordinator.TryOpenInitialPacketLease(
                datagram.Span,
                initialProtection,
                requireZeroTokenLength: false,
                allowClearedFixedBit: false,
                out QuicBufferLease openedPacket,
                out int payloadOffset,
                out int payloadLength))
            {
                if (isRetryBootstrapReplayCandidate)
                {
                    Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureOpen);
                }

                return Fail("open-initial-packet", "initial-packet-open-failed");
            }

            try
            {
            if (!TryValidateInitialCryptoPayload(openedPacket.Span.Slice(payloadOffset, payloadLength), out string initialCryptoValidationReason))
            {
                if (isRetryBootstrapReplayCandidate)
                {
                    Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailurePayload);
                }

                return Fail("validate-initial-crypto-payload", initialCryptoValidationReason);
            }

            if (!TryReadOpenedInitialPacketNumber(openedPacket.Span, payloadOffset, out ulong openedInitialPacketNumber))
            {
                return Fail("read-opened-initial-packet-number", "packet-number-read-failed");
            }

            uint selectedVersion = initialVersion;
            // CONTEXT: A fragmented Initial ClientHello can reach admission before the full ClientHello bytes
            // needed for transport-parameter parsing are available. Keeping the packet admitted lets the
            // replayed Initial datagram continue the transcript instead of dropping a valid handshake path.
            // SEE: code:src/Incursa.Quic/QuicTlsClientHelloExtensions.cs#TryReadClientHelloTransportParameters
            // SEE: code:src/Incursa.Quic/QuicListenerHost.cs#TryAdmitIncomingInitialConnectionAsync
            if (QuicTlsClientHelloExtensions.TryExtractOffsetZeroInitialCryptoFrameData(
                openedPacket.Span.Slice(payloadOffset, payloadLength),
                out ReadOnlySpan<byte> initialCryptoFrameData)
                && QuicTlsClientHelloExtensions.TryReadClientHelloTransportParameters(
                    initialCryptoFrameData,
                    out QuicTransportParameters? clientHelloTransportParameters)
                && clientHelloTransportParameters?.VersionInformation is QuicVersionInformation clientVersionInformation
                && QuicVersionNegotiation.TrySelectCompatibleVersion(
                    initialVersion,
                    clientVersionInformation.AvailableVersions,
                    ListenerSupportedVersions,
                    out uint negotiatedVersion))
            {
                selectedVersion = negotiatedVersion;
            }

            if (retryBootstrapEnabled)
            {
                if (isRetryBootstrapReplayCandidate)
                {
                    if (!TryValidateRetryBootstrapReplay(datagram.Span, pathIdentity))
                    {
                        switch (retryBootstrapReplayValidationFailureCode)
                        {
                            case RetryBootstrapReplayValidationFailureTokenParse:
                            case RetryBootstrapReplayValidationFailureTokenMismatch:
                            case RetryBootstrapReplayValidationFailureTokenValidation:
                            {
                                byte[] invalidTokenCloseServerSourceConnectionId =
                                    GenerateDistinctServerSourceConnectionId(initialDestinationConnectionId.Span);
                                _ = TrySendInitialCloseResponse(
                                    pathIdentity,
                                    initialVersion,
                                    initialDestinationConnectionId.Span,
                                    clientSourceConnectionId.Span,
                                    invalidTokenCloseServerSourceConnectionId,
                                    QuicTransportErrorCode.InvalidToken);
                                break;
                            }
                        }

                        return Fail("validate-retry-bootstrap-replay", "retry-bootstrap-replay-validation-failed");
                    }

                    if (retryBootstrapObservedInitialPacketNumberSet != 0
                        && openedInitialPacketNumber <= retryBootstrapLargestObservedInitialPacketNumber)
                    {
                        Interlocked.Exchange(
                            ref retryBootstrapReplayValidationFailureCode,
                            RetryBootstrapReplayValidationFailurePacketNumberReset);
                        TrySendProtocolViolationCloseResponse(pathIdentity);
                        return Fail("validate-retry-bootstrap-packet-number", "initial-packet-number-not-increased");
                    }

                    Interlocked.Exchange(ref retryBootstrapReplayValidated, 1);
                }
                else if (initialToken.Length > 0)
                {
                    QuicAddressValidationTokenValidationResult validationResult =
                        ValidateNewTokenForIncomingInitial(initialToken.Span, pathIdentity);
                    if (validationResult == QuicAddressValidationTokenValidationResult.Valid)
                    {
                        newTokenValidated = true;
                    }
                    else
                    {
                        if (!TryIssueRetryBootstrapResponse(
                            pathIdentity,
                            initialVersion,
                            initialDestinationConnectionId,
                            clientSourceConnectionId))
                        {
                            return Fail("issue-retry-bootstrap-for-invalid-token", "retry-bootstrap-send-failed");
                        }

                        ObserveRetryBootstrapInitialPacketNumber(openedInitialPacketNumber);

                        return Fail("issue-retry-bootstrap-for-invalid-token", "retry-bootstrap-sent");
                    }
                }
                else
                {
                    if (!TryIssueRetryBootstrapResponse(
                        pathIdentity,
                        initialVersion,
                        initialDestinationConnectionId,
                        clientSourceConnectionId))
                    {
                        return Fail("issue-retry-bootstrap", "retry-bootstrap-send-failed");
                    }

                    ObserveRetryBootstrapInitialPacketNumber(openedInitialPacketNumber);

                    return Fail("issue-retry-bootstrap", "retry-bootstrap-sent");
                }
            }
            else if (initialToken.Length > 0)
            {
                QuicAddressValidationTokenValidationResult validationResult =
                    ValidateNewTokenForIncomingInitial(initialToken.Span, pathIdentity);
                if (validationResult == QuicAddressValidationTokenValidationResult.Valid)
                {
                    newTokenValidated = true;
                }
            }

            byte[] serverSourceConnectionId = GenerateServerSourceConnectionId();
            runtime = CreateRuntime(selectedOptions, selectedVersion);
            if (newTokenValidated)
            {
                _ = runtime.TryMarkPeerAddressValidatedByAddressValidationToken(runtime.Clock.Ticks);
            }
            handle = endpoint.AllocateConnectionHandle();
            QuicServerConnectionLifetime lifetimeOwner = new(endpoint, handle, runtime);
            connection = new QuicConnection(runtime, selectedOptions, lifetimeOwner);

            if (!endpoint.TryRegisterConnection(handle, runtime)
                || !endpoint.TryRegisterConnectionId(handle, initialDestinationConnectionId.Span)
                || !endpoint.TryRegisterConnectionId(handle, serverSourceConnectionId, statelessResetConnectionId: 0UL)
                || !endpoint.TryUpdateEndpointBinding(handle, pathIdentity))
            {
                return Fail("register-runtime-endpoint", "endpoint-registration-failed");
            }

            runtime.SetLocalApiEventDispatcher(connectionEvent => endpoint.Host.TryPostEvent(handle, connectionEvent));
            runtime.SetStreamCapacityReleaseDispatcher(() => endpoint.Host.TryPostStreamCapacityRelease(handle));
            runtime.SetFlowControlCreditUpdateDispatcher(() => endpoint.Host.TryPostFlowControlCreditUpdate(handle));
            runtime.SetStreamOpenDispatcher((requestId, streamType) => endpoint.Host.TryPostStreamOpen(handle, requestId, streamType));
            runtime.SetStreamWriteDispatcher((requestId, actionKind, streamId, streamData, streamDataSuffix) => endpoint.Host.TryPostStreamWrite(handle, requestId, actionKind, streamId, streamData, streamDataSuffix));

            if (!connections.TryAdd(handle, new PendingConnectionState(handle, runtime, connection)))
            {
                return Fail("register-pending-connection", "pending-connection-registration-failed");
            }

            if (connections.Count > 1)
            {
                TryIncreaseSocketReceiveBuffer(socket);
            }

            if (!runtime.TryConfigurePeerInitialPacketProtection(initialVersion, initialDestinationConnectionId.Span)
                || !runtime.TryConfigureInitialPacketProtection(selectedVersion, initialDestinationConnectionId.Span)
                || !runtime.TrySetHandshakeDestinationConnectionId(clientSourceConnectionId.Span)
                || !runtime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId)
                || !runtime.TryConfigureLocalApplicationProtocols(applicationProtocols))
            {
                return Fail("configure-server-runtime-bootstrap", "runtime-bootstrap-configuration-failed");
            }

            using CancellationTokenSource acceptCancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);
            QuicServerConnectionOptions returnedOptions = await connectionOptionsCallback(
                connection,
                new SslClientHelloInfo(string.Empty, SslProtocols.Tls13),
                acceptCancellationSource.Token).ConfigureAwait(false);

            if (returnedOptions is null)
            {
                _ = TrySendConnectionRefusedCloseResponse(
                    pathIdentity,
                    initialVersion,
                    initialDestinationConnectionId.Span,
                    clientSourceConnectionId.Span,
                    serverSourceConnectionId);
                return Fail("select-server-options", "connection-options-callback-returned-null");
            }

            QuicServerConnectionSettings validatedOptions = QuicServerConnectionOptionsValidator.Capture(
                returnedOptions,
                "returnedOptions",
                applicationProtocols);

            ApplyReturnedOptions(selectedOptions, returnedOptions);
            ApplyReturnedInitialReceiveLimits(runtime, selectedOptions);
            ApplyReturnedInitialIncomingStreamLimits(runtime, selectedOptions);
            runtime.ConfigureAdaptiveRuntimePolicy(selectedOptions);
            connection.UpdateStreamCapacityCallback(selectedOptions.StreamCapacityCallback);

            if (!runtime.TryConfigureServerResumptionTicketIssuance(validatedOptions.EnableResumptionTickets)
                || !runtime.TryConfigureServerEarlyData(validatedOptions.EnableEarlyData)
                || !runtime.TryConfigureServerAuthenticationMaterial(
                    validatedOptions.ServerLeafCertificateDer,
                    validatedOptions.ServerLeafSigningPrivateKey,
                    selectedOptions.ServerAuthenticationOptions.ClientCertificateRequired,
                    selectedOptions.ServerAuthenticationOptions.CertificateChainPolicy,
                    selectedOptions.ServerAuthenticationOptions.CertificateRevocationCheckMode,
                    selectedOptions.ServerAuthenticationOptions.RemoteCertificateValidationCallback))
            {
                return Fail("configure-server-authentication", "server-authentication-configuration-failed");
            }

            if (!endpoint.Host.TryPostEvent(
                handle,
                new QuicConnectionHandshakeBootstrapRequestedEvent(
                    runtime.Clock.Ticks,
                    CreateLocalTransportParameters(
                        selectedOptions,
                        runtime.VersionProfile.SelectedVersion,
                        runtime.VersionProfile.SupportedVersions.Span,
                        serverSourceConnectionId,
                        retryBootstrapOriginalDestinationConnectionId is null
                            ? initialDestinationConnectionId.Span
                            : retryBootstrapOriginalDestinationConnectionId.Value.Span,
                        retryBootstrapSourceConnectionId is null ? ReadOnlySpan<byte>.Empty : retryBootstrapSourceConnectionId.Value.Span))))
            {
                return Fail("post-handshake-bootstrap", "handshake-bootstrap-post-failed");
            }

            admitted = true;
            if (retryBootstrapEnabled && Volatile.Read(ref retryBootstrapIssued) != 0)
            {
                Interlocked.Exchange(ref retryBootstrapReplayAdmitted, 1);
            }
            EmitListenerInitialAdmissionResult(pathIdentity, "admit-initial-connection", succeeded: true, "connection-admitted");
            return true;
            }
            finally
            {
                openedPacket.Dispose();
            }
        }
        catch (Exception ex)
        {
            EmitListenerInitialAdmissionResult(
                pathIdentity,
                "admit-initial-connection",
                succeeded: false,
                FormatAdmissionExceptionReason(ex));
            return false;
        }
        finally
        {
            if (!admitted)
            {
                if (!EqualityComparer<QuicConnectionHandle>.Default.Equals(handle, default))
                {
                    connections.TryRemove(handle, out _);
                    endpoint.TryUnregisterConnection(handle);
                }

                try
                {
                    if (connection is not null)
                    {
                        await connection.DisposeAsync().ConfigureAwait(false);
                    }
                    else if (runtime is not null)
                    {
                        await runtime.DisposeAsync().ConfigureAwait(false);
                    }
                }
                catch
                {
                    // Best-effort cleanup only.
                }
            }
        }
    }

    private static string FormatAdmissionExceptionReason(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return string.IsNullOrWhiteSpace(exception.Message)
            ? $"exception:{exception.GetType().Name}"
            : $"exception:{exception.GetType().Name}:{exception.Message}";
    }

    private static bool TryValidateInitialCryptoPayload(ReadOnlySpan<byte> payload, out string failureReason)
    {
        failureReason = "crypto-payload-invalid";
        bool sawCryptoFrame = false;
        int payloadOffset = 0;

        while (payloadOffset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[payloadOffset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                if (paddingBytesConsumed <= 0)
                {
                    failureReason = "invalid-initial-padding-frame";
                    return false;
                }

                payloadOffset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                if (pingBytesConsumed <= 0)
                {
                    failureReason = "invalid-initial-ping-frame";
                    return false;
                }

                payloadOffset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryConsumeAckFrame(remaining, out int ackBytesConsumed))
            {
                if (ackBytesConsumed <= 0)
                {
                    failureReason = "invalid-initial-ack-frame";
                    return false;
                }

                payloadOffset += ackBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out _, out int bytesConsumed)
                || bytesConsumed <= 0)
            {
                failureReason = "invalid-initial-crypto-frame";
                return false;
            }

            sawCryptoFrame = true;
            payloadOffset += bytesConsumed;
        }

        if (!sawCryptoFrame)
        {
            failureReason = "missing-initial-crypto-frame";
        }

        return sawCryptoFrame;
    }

    private static QuicConnectionPathIdentity CreatePathIdentity(IPEndPoint remoteEndPoint, IPEndPoint localEndPoint)
    {
        return new QuicConnectionPathIdentity(
            QuicAddressFormatting.Format(remoteEndPoint.Address),
            QuicAddressFormatting.Format(localEndPoint.Address),
            remoteEndPoint.Port,
            localEndPoint.Port);
    }

    private static byte[] GenerateServerSourceConnectionId()
    {
        byte[] connectionId = new byte[RouteConnectionIdLength];
        RandomNumberGenerator.Fill(connectionId);
        return connectionId;
    }

    internal static byte[] GenerateDistinctServerSourceConnectionId(ReadOnlySpan<byte> disallowedConnectionId)
    {
        byte[] connectionId;

        do
        {
            connectionId = GenerateServerSourceConnectionId();
        }
        while (connectionId.AsSpan().SequenceEqual(disallowedConnectionId));

        return connectionId;
    }

    private bool TryIssueRetryBootstrapResponse(
        QuicConnectionPathIdentity pathIdentity,
        uint version,
        ReadOnlyMemory<byte> originalDestinationConnectionId,
        ReadOnlyMemory<byte> clientSourceConnectionId)
    {
        int remotePort = pathIdentity.RemotePort
            ?? throw new InvalidOperationException("The listener connection path is missing a remote port.");
        bool hasRetryBootstrapState =
            retryBootstrapOriginalDestinationConnectionId is not null
            && retryBootstrapSourceConnectionId is not null
            && retryBootstrapToken is not null
            && retryBootstrapPathIdentity is not null
            && retryBootstrapVersion.HasValue;

        ReadOnlyMemory<byte> retryBootstrapOriginalDestinationConnectionIdBytes = hasRetryBootstrapState
            ? this.retryBootstrapOriginalDestinationConnectionId!.Value
            : originalDestinationConnectionId.ToArray();
        ReadOnlyMemory<byte> retrySourceConnectionId = hasRetryBootstrapState
            ? this.retryBootstrapSourceConnectionId!.Value
            : GenerateDistinctServerSourceConnectionId(retryBootstrapOriginalDestinationConnectionIdBytes.Span);
        ReadOnlyMemory<byte> retryToken = hasRetryBootstrapState
            ? this.retryBootstrapToken!.Value
            : addressValidationTokenProtector.IssueNewToken(
                pathIdentity.RemoteAddress,
                remotePort,
                DateTimeOffset.UtcNow,
                RetryBootstrapTokenLifetime).AsMemory();
        uint retryVersion = hasRetryBootstrapState
            ? retryBootstrapVersion!.Value
            : version;

        if (!QuicRetryIntegrity.TryBuildRetryPacket(
            retryVersion,
            retryBootstrapOriginalDestinationConnectionIdBytes.Span,
            clientSourceConnectionId.Span,
            retrySourceConnectionId.Span,
            retryToken.Span,
            out byte[] retryPacket))
        {
            return false;
        }

        try
        {
            EndPoint remoteEndPoint = new IPEndPoint(
                IPAddress.Parse(pathIdentity.RemoteAddress),
                remotePort);

            int bytesSent = socket.SendTo(retryPacket.AsSpan(), SocketFlags.None, remoteEndPoint);
            if (bytesSent != retryPacket.Length)
            {
                return false;
            }
        }
        catch (ObjectDisposedException) when (shutdown.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException) when (shutdown.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException ex)
        {
            QuicMetrics.RecordUdpError(QuicTlsRole.Server, "send", ex.SocketErrorCode);
            return false;
        }

        if (!hasRetryBootstrapState)
        {
            this.retryBootstrapOriginalDestinationConnectionId = retryBootstrapOriginalDestinationConnectionIdBytes;
            retryBootstrapSourceConnectionId = retrySourceConnectionId;
            retryBootstrapToken = retryToken;
            retryBootstrapPathIdentity = pathIdentity;
            retryBootstrapVersion = retryVersion;
            retryBootstrapTokenHex = Convert.ToHexString(retryToken.Span);
        }

        Interlocked.Exchange(ref retryBootstrapIssued, 1);
        return true;
    }

    private bool TryIssueRetryBootstrapResponseFromZeroRttDatagram(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity)
    {
        if (!QuicPacketParsing.TryParseLongHeaderMemoryFields(
                datagram,
                out byte headerControlBits,
                out uint version,
                out ReadOnlyMemory<byte> destinationConnectionId,
                out ReadOnlyMemory<byte> sourceConnectionId,
                out _)
            || !QuicVersionNegotiation.IsSupportedTransportVersion(version)
            || !QuicVersionNegotiation.IsLongHeaderPacketType(
                version,
                (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift),
                QuicLongPacketType.ZeroRtt))
        {
            return false;
        }

        return TryIssueRetryBootstrapResponse(
            pathIdentity,
            version,
            destinationConnectionId,
            sourceConnectionId);
    }

    private bool TryValidateRetryBootstrapReplay(
        ReadOnlySpan<byte> datagram,
        QuicConnectionPathIdentity pathIdentity)
    {
        if (retryBootstrapOriginalDestinationConnectionId is null
            || retryBootstrapSourceConnectionId is null
            || retryBootstrapToken is null
            || retryBootstrapPathIdentity is null)
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, 1);
            return false;
        }

        if (!QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket retryHeader))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureParseHeader);
            return false;
        }

        if (!QuicVersionNegotiation.IsSupportedTransportVersion(retryHeader.Version)
            || !retryBootstrapVersion.HasValue
            || retryHeader.Version != retryBootstrapVersion.Value
            || !QuicVersionNegotiation.IsLongHeaderPacketType(
                retryHeader.Version,
                retryHeader.LongPacketTypeBits,
                QuicLongPacketType.Initial))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureVersionOrType);
            return false;
        }

        if (!retryHeader.DestinationConnectionId.SequenceEqual(retryBootstrapSourceConnectionId.Value.Span))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureDestinationConnectionIdMismatch);
            return false;
        }

        if (!TryParseInitialTokenSpan(retryHeader.VersionSpecificData, out ReadOnlySpan<byte> retryToken))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureTokenParse);
            return false;
        }

        retryBootstrapReplayTokenHex = Convert.ToHexString(retryToken);

        if (!retryToken.SequenceEqual(retryBootstrapToken.Value.Span))
        {
            Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, RetryBootstrapReplayValidationFailureTokenMismatch);
            return false;
        }

        if (!HasSameRemoteEndpoint(pathIdentity, retryBootstrapPathIdentity.Value))
        {
            Interlocked.Exchange(
                ref retryBootstrapReplayValidationFailureCode,
                RetryBootstrapReplayValidationFailureSourceEndpointMismatch);
            return false;
        }

        QuicAddressValidationTokenValidationResult validationResult =
            addressValidationTokenProtector.ValidateNewToken(
                retryToken,
                pathIdentity.RemoteAddress,
                pathIdentity.RemotePort ?? throw new InvalidOperationException("The listener connection path is missing a remote port."),
                DateTimeOffset.UtcNow);
        if (validationResult != QuicAddressValidationTokenValidationResult.Valid)
        {
            Interlocked.Exchange(
                ref retryBootstrapReplayValidationFailureCode,
                RetryBootstrapReplayValidationFailureTokenValidation);
            return false;
        }

        Interlocked.Exchange(ref retryBootstrapReplayValidationFailureCode, 0);
        return true;
    }

    private void ObserveRetryBootstrapInitialPacketNumber(ulong packetNumber)
    {
        if (retryBootstrapObservedInitialPacketNumberSet == 0)
        {
            retryBootstrapLargestObservedInitialPacketNumber = packetNumber;
            retryBootstrapObservedInitialPacketNumberSet = 1;
            return;
        }

        retryBootstrapLargestObservedInitialPacketNumber = Math.Max(
            retryBootstrapLargestObservedInitialPacketNumber,
            packetNumber);
    }

    private static bool TryReadOpenedInitialPacketNumber(
        ReadOnlySpan<byte> openedPacket,
        int payloadOffset,
        out ulong packetNumber)
    {
        packetNumber = default;

        if (openedPacket.Length == 0
            || payloadOffset <= 0
            || payloadOffset > openedPacket.Length)
        {
            return false;
        }

        int packetNumberLength = (openedPacket[0] & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        if (packetNumberLength < 1 || packetNumberLength > sizeof(uint))
        {
            return false;
        }

        int packetNumberOffset = payloadOffset - packetNumberLength;
        if (packetNumberOffset < 1 || packetNumberOffset + packetNumberLength > openedPacket.Length)
        {
            return false;
        }

        ulong value = 0;
        for (int index = 0; index < packetNumberLength; index++)
        {
            value = (value << BitsPerByte) | openedPacket[packetNumberOffset + index];
        }

        packetNumber = value;
        return true;
    }

    private static bool HasSameRemoteEndpoint(
        QuicConnectionPathIdentity candidate,
        QuicConnectionPathIdentity expected)
    {
        return string.Equals(candidate.RemoteAddress, expected.RemoteAddress, StringComparison.Ordinal)
            && candidate.RemotePort == expected.RemotePort;
    }

    private QuicAddressValidationTokenValidationResult ValidateNewTokenForIncomingInitial(
        ReadOnlySpan<byte> initialToken,
        QuicConnectionPathIdentity pathIdentity)
    {
        Interlocked.Exchange(ref newTokenValidationAttempted, 1);
        newTokenValidationTokenHex = Convert.ToHexString(initialToken);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        QuicAddressValidationTokenValidationResult result =
            addressValidationTokenProtector.ValidateNewToken(initialToken, pathIdentity.RemoteAddress, now);
        if (result == QuicAddressValidationTokenValidationResult.Valid)
        {
            if (!QuicAddressValidationTokenProtector.TryGetNewTokenExpiration(initialToken, out DateTimeOffset expiresAt))
            {
                result = QuicAddressValidationTokenValidationResult.Malformed;
            }
            else if (!addressValidationTokenReplayCache.TryConsume(initialToken, expiresAt, now))
            {
                result = QuicAddressValidationTokenValidationResult.Replayed;
            }
        }

        if (result == QuicAddressValidationTokenValidationResult.Valid)
        {
            Interlocked.Exchange(ref newTokenValidationSucceeded, 1);
            Interlocked.Exchange(ref newTokenValidationFailureCode, 0);
        }
        else
        {
            Interlocked.Exchange(ref newTokenValidationSucceeded, 0);
            Interlocked.Exchange(ref newTokenValidationFailureCode, (int)result);
        }

        return result;
    }

    private static bool TryParseInitialToken(ReadOnlyMemory<byte> versionSpecificData, out ReadOnlyMemory<byte> retryToken)
    {
        retryToken = default;

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData.Span, out ulong tokenLength, out int tokenLengthBytes)
            || tokenLength > (ulong)(versionSpecificData.Length - tokenLengthBytes))
        {
            return false;
        }

        retryToken = versionSpecificData.Slice(tokenLengthBytes, (int)tokenLength);
        return true;
    }

    private static bool TryParseInitialTokenSpan(ReadOnlySpan<byte> versionSpecificData, out ReadOnlySpan<byte> retryToken)
    {
        retryToken = default;

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes)
            || tokenLength > (ulong)(versionSpecificData.Length - tokenLengthBytes))
        {
            return false;
        }

        retryToken = versionSpecificData.Slice(tokenLengthBytes, (int)tokenLength);
        return true;
    }

    private static QuicTransportParameters CreateLocalTransportParameters(
        QuicServerConnectionOptions options,
        uint chosenVersion,
        ReadOnlySpan<uint> supportedVersions,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> originalDestinationConnectionId = default,
        ReadOnlySpan<byte> retrySourceConnectionId = default)
    {
        QuicReceiveWindowSizes receiveWindowSizes = options.InitialReceiveWindowSizes;

        return new QuicTransportParameters
        {
            MaxIdleTimeout = QuicTransportParameterTimeUnits.IdleTimeoutToMaxIdleTimeoutMilliseconds(options.IdleTimeout),
            InitialMaxData = (ulong)Math.Max(0, receiveWindowSizes.Connection),
            InitialMaxStreamDataBidiLocal = (ulong)Math.Max(0, receiveWindowSizes.LocallyInitiatedBidirectionalStream),
            InitialMaxStreamDataBidiRemote = (ulong)Math.Max(0, receiveWindowSizes.RemotelyInitiatedBidirectionalStream),
            InitialMaxStreamDataUni = (ulong)Math.Max(0, receiveWindowSizes.UnidirectionalStream),
            InitialMaxStreamsBidi = (ulong)Math.Max(0, options.MaxInboundBidirectionalStreams),
            InitialMaxStreamsUni = (ulong)Math.Max(0, options.MaxInboundUnidirectionalStreams),
            ActiveConnectionIdLimit = MinimumActiveConnectionIdLimit,
            PreferredAddress = options.PreferredAddress,
            OriginalDestinationConnectionId = originalDestinationConnectionId.IsEmpty ? null : originalDestinationConnectionId.ToArray(),
            InitialSourceConnectionId = sourceConnectionId.ToArray(),
            RetrySourceConnectionId = retrySourceConnectionId.IsEmpty ? null : retrySourceConnectionId.ToArray(),
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = chosenVersion,
                AvailableVersions = supportedVersions.ToArray(),
            },
            GreaseQuicBit = true,
            MaxDatagramFrameSize = options.MaxDatagramFrameSize > 0
                ? (ulong)options.MaxDatagramFrameSize
                : null,
        };
    }

    internal static Exception MapTerminalState(QuicConnectionTerminalState terminalState)
    {
        if (terminalState.Close.TransportErrorCode.HasValue)
        {
            return new QuicException(
                QuicError.TransportError,
                null,
                (long)terminalState.Close.TransportErrorCode.Value,
                terminalState.Close.ReasonPhrase ?? "The listener connection terminated during establishment.");
        }

        if (terminalState.Origin == QuicConnectionCloseOrigin.IdleTimeout)
        {
            return new QuicException(
                QuicError.ConnectionIdle,
                null,
                terminalState.Close.ReasonPhrase ?? "The listener connection idled before establishment completed.");
        }

        if (terminalState.Origin == QuicConnectionCloseOrigin.VersionNegotiation)
        {
            return new QuicException(
                QuicError.VersionNegotiationError,
                null,
                terminalState.Close.ReasonPhrase ?? "The listener connection could not negotiate a compatible version.");
        }

        long? applicationErrorCode = terminalState.Close.ApplicationErrorCode.HasValue
            ? checked((long)terminalState.Close.ApplicationErrorCode.Value)
            : null;

        return new QuicException(
            QuicError.ConnectionAborted,
            applicationErrorCode,
            terminalState.Close.ReasonPhrase ?? "The listener connection terminated during establishment.");
    }

    private async Task QueueAcceptedConnectionAsync(QuicConnection connection)
    {
        try
        {
            await acceptQueue.Writer.WriteAsync(connection, shutdown.Token).ConfigureAwait(false);
        }
        catch
        {
            try
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // Best-effort cleanup only.
            }
        }
    }

    private async Task QueueConnectionFailureAsync(QuicConnection connection, Exception exception)
    {
        try
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
            // Best-effort cleanup only.
        }

        try
        {
            await acceptQueue.Writer.WriteAsync(exception, shutdown.Token).ConfigureAwait(false);
        }
        catch
        {
            // The listener is shutting down or the queue is closed.
        }
    }

    private static QuicConnection UnwrapQueuedItem(object item)
    {
        if (item is QuicConnection connection)
        {
            return connection;
        }

        if (item is Exception exception)
        {
            throw exception;
        }

        throw new InvalidOperationException("Unexpected listener queue item.");
    }

    internal QuicConnectionRuntime CreateRuntime(
        QuicServerConnectionOptions options,
        uint initialVersion = QuicVersionNegotiation.Version1)
    {
        QuicReceiveWindowSizes receiveWindowSizes = options.InitialReceiveWindowSizes;
        uint[] supportedVersions = BuildRuntimeSupportedVersions(initialVersion);
        QuicConnectionStreamState bookkeeping = new(new QuicConnectionStreamStateOptions(
            IsServer: true,
            InitialConnectionReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.Connection),
            InitialConnectionSendLimit: 0,
            InitialIncomingBidirectionalStreamLimit: (ulong)Math.Max(0, options.MaxInboundBidirectionalStreams),
            InitialIncomingUnidirectionalStreamLimit: (ulong)Math.Max(0, options.MaxInboundUnidirectionalStreams),
            InitialPeerBidirectionalStreamLimit: 0,
            InitialPeerUnidirectionalStreamLimit: 0,
            InitialLocalBidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.LocallyInitiatedBidirectionalStream),
            InitialPeerBidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.RemotelyInitiatedBidirectionalStream),
            InitialPeerUnidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.UnidirectionalStream),
            InitialLocalBidirectionalSendLimit: (ulong)Math.Max(0, receiveWindowSizes.LocallyInitiatedBidirectionalStream),
            InitialLocalUnidirectionalSendLimit: (ulong)Math.Max(0, receiveWindowSizes.UnidirectionalStream),
            InitialPeerBidirectionalSendLimit: 0));
        IQuicDiagnosticsSink? diagnosticsSink = diagnosticsSinkFactory?.Invoke();

        return new QuicConnectionRuntime(
            bookkeeping,
            tlsRole: QuicTlsRole.Server,
            diagnosticsSink: QuicDiagnostics.ResolveConnectionSink(diagnosticsSink),
            enableRandomizedSpinBitSelection: true,
            supportedVersions: supportedVersions,
            selectedCipherSuite: options.SelectedCipherSuite,
            enableServerEarlyData: options.EnableEarlyData,
            serverResumptionTicketStore: serverResumptionTicketStore,
            tlsKeyLogSecretObserver: tlsKeyLogSecretObserver,
            maximumInboundDatagramQueueSize: GetEffectiveInboundDatagramQueueSize(options),
            applicationSendTurnPlanner: applicationSendTurnPlannerFactory?.Invoke());
    }

    private static int GetEffectiveInboundDatagramQueueSize(QuicConnectionOptions options)
        => options.MaxDatagramFrameSize > 0 ? options.MaxInboundDatagramQueueSize : 0;

    private static uint[] BuildRuntimeSupportedVersions(uint initialVersion)
    {
        bool containsInitialVersion = Array.IndexOf(ListenerSupportedVersions, initialVersion) >= 0;
        uint[] supportedVersions = new uint[ListenerSupportedVersions.Length + (containsInitialVersion ? 0 : 1)];
        supportedVersions[0] = initialVersion;

        int index = 1;
        for (int i = 0; i < ListenerSupportedVersions.Length; i++)
        {
            uint version = ListenerSupportedVersions[i];
            if (version == initialVersion)
            {
                continue;
            }

            supportedVersions[index++] = version;
        }

        return supportedVersions;
    }

    private sealed class PendingConnectionState
    {
        private const int AcceptedStatus = 1;
        private const int FailedStatus = 2;
        private int status;

        public PendingConnectionState(
            QuicConnectionHandle handle,
            QuicConnectionRuntime runtime,
            QuicConnection connection)
        {
            Handle = handle;
            Runtime = runtime;
            Connection = connection;
            FlowLabelSeed = unchecked((uint)RandomNumberGenerator.GetInt32(1, int.MaxValue));
        }

        public QuicConnectionHandle Handle { get; }

        public QuicConnectionRuntime Runtime { get; }

        public QuicConnection Connection { get; }

        public uint FlowLabelSeed { get; }

        public ConcurrentQueue<QuicConnectionTransitionResult> TransitionHistory { get; } = new();

        public bool IsPending => Volatile.Read(ref status) == 0;

        private QuicConnectionPathIdentity? cachedRemoteSocketAddressPathIdentity;

        private SocketAddress? cachedRemoteSocketAddress;

        public SocketAddress GetRemoteSocketAddress(QuicConnectionPathIdentity pathIdentity)
        {
            if (cachedRemoteSocketAddress is not null
                && cachedRemoteSocketAddressPathIdentity is QuicConnectionPathIdentity cachedPathIdentity
                && cachedPathIdentity.Equals(pathIdentity))
            {
                return cachedRemoteSocketAddress;
            }

            SocketAddress socketAddress = CreateRemoteSocketAddress(pathIdentity);
            cachedRemoteSocketAddressPathIdentity = pathIdentity;
            cachedRemoteSocketAddress = socketAddress;
            return socketAddress;
        }

        public bool TryMarkAccepted()
        {
            return Interlocked.CompareExchange(ref status, AcceptedStatus, 0) == 0;
        }

        public bool TryMarkFailed()
        {
            return Interlocked.CompareExchange(ref status, FailedStatus, 0) == 0;
        }
    }

    private sealed class QuicServerConnectionLifetime : IAsyncDisposable
    {
        private readonly QuicConnectionRuntimeEndpoint endpoint;
        private readonly QuicConnectionHandle handle;
        private readonly QuicConnectionRuntime runtime;
        private int disposed;

        public QuicServerConnectionLifetime(
            QuicConnectionRuntimeEndpoint endpoint,
            QuicConnectionHandle handle,
            QuicConnectionRuntime runtime)
        {
            this.endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
            this.handle = handle;
            this.runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            endpoint.TryUnregisterConnection(handle);
            await runtime.DisposeAsync().ConfigureAwait(false);
        }
    }

    internal static void ApplyReturnedOptions(QuicServerConnectionOptions selectedOptions, QuicServerConnectionOptions returnedOptions)
    {
        selectedOptions.DefaultCloseErrorCode = returnedOptions.DefaultCloseErrorCode;
        selectedOptions.DefaultStreamErrorCode = returnedOptions.DefaultStreamErrorCode;
        selectedOptions.HandshakeTimeout = returnedOptions.HandshakeTimeout;
        selectedOptions.IdleTimeout = returnedOptions.IdleTimeout;
        selectedOptions.KeepAliveInterval = returnedOptions.KeepAliveInterval;
        selectedOptions.MaxInboundBidirectionalStreams = returnedOptions.MaxInboundBidirectionalStreams;
        selectedOptions.MaxInboundUnidirectionalStreams = returnedOptions.MaxInboundUnidirectionalStreams;
        selectedOptions.StreamCapacityCallback = returnedOptions.StreamCapacityCallback;
        selectedOptions.ServerAuthenticationOptions = returnedOptions.ServerAuthenticationOptions;
        selectedOptions.EnableResumptionTickets = returnedOptions.EnableResumptionTickets;
        selectedOptions.EnableEarlyData = returnedOptions.EnableEarlyData;
        selectedOptions.PreferredAddress = returnedOptions.PreferredAddress;
        selectedOptions.ForcedReceiveCreditPolicyMode = returnedOptions.ForcedReceiveCreditPolicyMode;
        selectedOptions.ForcedApplicationSendTurnPolicyMode = returnedOptions.ForcedApplicationSendTurnPolicyMode;
        selectedOptions.AdaptiveRuntimeShadowEnabled = returnedOptions.AdaptiveRuntimeShadowEnabled;
        selectedOptions.AdaptiveRuntimeShadowEpochInterval = returnedOptions.AdaptiveRuntimeShadowEpochInterval;
        selectedOptions.AdaptiveRuntimeShadowEpochSink = returnedOptions.AdaptiveRuntimeShadowEpochSink;
        selectedOptions.ApplicationSendTurnPolicyProvenanceSink = returnedOptions.ApplicationSendTurnPolicyProvenanceSink;
        selectedOptions.ApplicationSendTurnObservationMode = returnedOptions.ApplicationSendTurnObservationMode;
        selectedOptions.ApplicationSendTurnEvidenceSink = returnedOptions.ApplicationSendTurnEvidenceSink;

        QuicReceiveWindowSizes returnedWindowSizes = returnedOptions.InitialReceiveWindowSizes;
        selectedOptions.InitialReceiveWindowSizes = new QuicReceiveWindowSizes
        {
            Connection = returnedWindowSizes.Connection,
            LocallyInitiatedBidirectionalStream = returnedWindowSizes.LocallyInitiatedBidirectionalStream,
            RemotelyInitiatedBidirectionalStream = returnedWindowSizes.RemotelyInitiatedBidirectionalStream,
            UnidirectionalStream = returnedWindowSizes.UnidirectionalStream,
        };
    }

    private static void ApplyReturnedInitialReceiveLimits(
        QuicConnectionRuntime runtime,
        QuicServerConnectionOptions selectedOptions)
    {
        QuicReceiveWindowSizes receiveWindowSizes = selectedOptions.InitialReceiveWindowSizes;
        _ = runtime.StreamRegistry.Bookkeeping.TryApplyInitialReceiveLimits(
            connectionReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.Connection),
            localBidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.LocallyInitiatedBidirectionalStream),
            peerBidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.RemotelyInitiatedBidirectionalStream),
            peerUnidirectionalReceiveLimit: (ulong)Math.Max(0, receiveWindowSizes.UnidirectionalStream));
    }

    private static void ApplyReturnedInitialIncomingStreamLimits(
        QuicConnectionRuntime runtime,
        QuicServerConnectionOptions selectedOptions)
    {
        _ = runtime.StreamRegistry.Bookkeeping.TryApplyInitialIncomingStreamLimits(
            bidirectionalStreamLimit: (ulong)Math.Max(0, selectedOptions.MaxInboundBidirectionalStreams),
            unidirectionalStreamLimit: (ulong)Math.Max(0, selectedOptions.MaxInboundUnidirectionalStreams));
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicListenerHost));
        }
    }
}
