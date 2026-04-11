using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0001">The approved public facade now includes QuicConnection, QuicStream, QuicConnectionOptions, QuicReceiveWindowSizes, QuicAbortDirection, QuicError, QuicException, QuicListener, QuicListenerOptions, QuicClientConnectionOptions, QuicServerConnectionOptions, QuicStreamCapacityChangedArgs, and the corrected QuicStreamType. The client entry point is now public, while broader middleware-style surface remains deferred.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0001")]
public sealed class REQ_QUIC_API_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PublicApiSurface_ContainsOnlyTheApprovedFacadeTypes()
    {
        string[] exportedTypeNames = typeof(QuicConnection).Assembly
            .GetExportedTypes()
            .Select(type => type.FullName ?? type.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        string[] expectedTypeNames =
        [
            "Incursa.Quic.QuicAbortDirection",
            "Incursa.Quic.QuicClientConnectionOptions",
            "Incursa.Quic.QuicConnection",
            "Incursa.Quic.QuicConnectionOptions",
            "Incursa.Quic.QuicError",
            "Incursa.Quic.QuicException",
            "Incursa.Quic.QuicListener",
            "Incursa.Quic.QuicListenerOptions",
            "Incursa.Quic.QuicReceiveWindowSizes",
            "Incursa.Quic.QuicServerConnectionOptions",
            "Incursa.Quic.QuicStream",
            "Incursa.Quic.QuicStreamCapacityChangedArgs",
            "Incursa.Quic.QuicStreamType",
        ];

        Assert.Equal(expectedTypeNames, exportedTypeNames);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HelperRuntimeAndWireTypesRemainInternal()
    {
        Type[] internalTypes =
        [
            typeof(QuicConnectionCloseFrame),
            typeof(QuicConnectionLifecycleState),
            typeof(QuicConnectionEndpointHost),
            typeof(QuicConnectionRuntimeEndpoint),
            typeof(QuicClientConnectionHost),
            typeof(QuicClientConnectionOptionsValidator),
            typeof(QuicListenerHost),
            typeof(QuicConnectionRuntime),
            typeof(QuicConnectionStreamRegistry),
            typeof(QuicConnectionStreamState),
            typeof(QuicFrameCodec),
            typeof(QuicIdleTimeoutState),
            typeof(QuicPacketParser),
            typeof(QuicStreamFrame),
            typeof(QuicStreamId),
            typeof(QuicTransportErrorCode),
            typeof(QuicTransportParametersCodec),
            typeof(QuicVersionNegotiation),
        ];

        Assert.All(internalTypes, type => Assert.False(type.IsPublic, $"{type.FullName} leaked through the public boundary."));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicClassificationEnums_UseTheApprovedReferenceValues()
    {
        Assert.Equal(QuicAbortDirection.Read | QuicAbortDirection.Write, QuicAbortDirection.Both);

        Assert.Equal(new[]
        {
            QuicAbortDirection.Read,
            QuicAbortDirection.Write,
            QuicAbortDirection.Both,
        }, Enum.GetValues<QuicAbortDirection>());

        Assert.Equal(new[]
        {
            QuicError.Success,
            QuicError.InternalError,
            QuicError.ConnectionAborted,
            QuicError.StreamAborted,
            QuicError.ConnectionTimeout,
            QuicError.ConnectionRefused,
            QuicError.VersionNegotiationError,
            QuicError.ConnectionIdle,
            QuicError.OperationAborted,
            QuicError.AlpnInUse,
            QuicError.TransportError,
            QuicError.CallbackError,
        }, Enum.GetValues<QuicError>());

        Assert.Equal(new[]
        {
            QuicStreamType.Unidirectional,
            QuicStreamType.Bidirectional,
        }, Enum.GetValues<QuicStreamType>());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnectionOptionsExposeOnlyTheSharedKnobs()
    {
        TestQuicConnectionOptions options = new();

        Assert.Equal(-1, options.DefaultCloseErrorCode);
        Assert.Equal(-1, options.DefaultStreamErrorCode);
        Assert.Equal(TimeSpan.FromSeconds(10), options.HandshakeTimeout);
        Assert.Equal(TimeSpan.Zero, options.IdleTimeout);
        Assert.Equal(Timeout.InfiniteTimeSpan, options.KeepAliveInterval);
        Assert.Equal(0, options.MaxInboundBidirectionalStreams);
        Assert.Equal(0, options.MaxInboundUnidirectionalStreams);
        Assert.Null(options.StreamCapacityCallback);
        Assert.NotNull(options.InitialReceiveWindowSizes);
        Assert.Equal(16 * 1024 * 1024, options.InitialReceiveWindowSizes.Connection);
        Assert.Equal(64 * 1024, options.InitialReceiveWindowSizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(64 * 1024, options.InitialReceiveWindowSizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(64 * 1024, options.InitialReceiveWindowSizes.UnidirectionalStream);

        string[] propertyNames = typeof(QuicConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        string[] expectedPropertyNames =
        [
            "DefaultCloseErrorCode",
            "DefaultStreamErrorCode",
            "HandshakeTimeout",
            "IdleTimeout",
            "InitialReceiveWindowSizes",
            "KeepAliveInterval",
            "MaxInboundBidirectionalStreams",
            "MaxInboundUnidirectionalStreams",
            "StreamCapacityCallback",
        ];

        Assert.Equal(expectedPropertyNames, propertyNames);

        PropertyInfo? callbackProperty = typeof(QuicConnectionOptions).GetProperty(nameof(QuicConnectionOptions.StreamCapacityCallback));
        Assert.NotNull(callbackProperty);
        Assert.Equal(typeof(Action<QuicConnection, QuicStreamCapacityChangedArgs>), callbackProperty!.PropertyType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnection_ExposesTheApprovedStaticConnectEntryPoint()
    {
        MethodInfo? method = typeof(QuicConnection).GetMethod(
            nameof(QuicConnection.ConnectAsync),
            BindingFlags.Public | BindingFlags.Static,
            [typeof(QuicClientConnectionOptions), typeof(CancellationToken)]);

        Assert.NotNull(method);
        Assert.Equal(typeof(ValueTask<QuicConnection>), method.ReturnType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicReceiveWindowSizesExposeTheApprovedWindowValues()
    {
        QuicReceiveWindowSizes sizes = new();

        Assert.Equal(16 * 1024 * 1024, sizes.Connection);
        Assert.Equal(64 * 1024, sizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(64 * 1024, sizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(64 * 1024, sizes.UnidirectionalStream);

        sizes.Connection = 1;
        sizes.LocallyInitiatedBidirectionalStream = 2;
        sizes.RemotelyInitiatedBidirectionalStream = 3;
        sizes.UnidirectionalStream = 4;

        Assert.Equal(1, sizes.Connection);
        Assert.Equal(2, sizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(3, sizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(4, sizes.UnidirectionalStream);

        string[] propertyNames = typeof(QuicReceiveWindowSizes)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "Connection",
            "LocallyInitiatedBidirectionalStream",
            "RemotelyInitiatedBidirectionalStream",
            "UnidirectionalStream",
        }, propertyNames);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicStreamCapacityChangedArgsExposeTheApprovedDeltaShape()
    {
        QuicStreamCapacityChangedArgs args = new()
        {
            BidirectionalIncrement = 7,
            UnidirectionalIncrement = 11,
        };

        Assert.Equal(7, args.BidirectionalIncrement);
        Assert.Equal(11, args.UnidirectionalIncrement);
        Assert.True(typeof(QuicStreamCapacityChangedArgs).IsValueType);

        string[] propertyNames = typeof(QuicStreamCapacityChangedArgs)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "BidirectionalIncrement",
            "UnidirectionalIncrement",
        }, propertyNames);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task QuicConnection_CloseAsync_ProjectsTheRuntimeTerminalState()
    {
        QuicConnectionRuntime runtime = CreateConnectionRuntime();
        TestQuicConnectionOptions options = new();
        QuicConnection connection = new(runtime, options);

        await connection.CloseAsync(42);

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState.Value.Origin);
        Assert.Equal(42UL, runtime.TerminalState.Value.Close.ApplicationErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.TransportErrorCode);

        await connection.DisposeAsync();

        Assert.True(runtime.IsDisposed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task QuicConnection_DisposeAsync_UsesTheConfiguredDefaultCloseCode()
    {
        QuicConnectionRuntime runtime = CreateConnectionRuntime();
        TestQuicConnectionOptions options = new()
        {
            DefaultCloseErrorCode = 77,
        };
        QuicConnection connection = new(runtime, options);

        await connection.DisposeAsync();

        Assert.True(runtime.IsDisposed);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState.Value.Origin);
        Assert.Equal(77UL, runtime.TerminalState.Value.Close.ApplicationErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task QuicStream_ReadAndDispose_SurfaceTheStreamStateSeam()
    {
        QuicConnectionStreamState bookkeeping = CreateReadableStreamBookkeeping();
        byte[] expectedPayload = [0x11, 0x22, 0x33, 0x44];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 3, expectedPayload, offset: 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(bookkeeping.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        QuicStream stream = new(bookkeeping, 3);

        Assert.Equal(QuicStreamType.Unidirectional, stream.Type);
        Assert.True(stream.CanRead);
        Assert.False(stream.CanWrite);

        byte[] buffer = new byte[expectedPayload.Length];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        Assert.Equal(expectedPayload.Length, bytesRead);
        Assert.True(expectedPayload.AsSpan().SequenceEqual(buffer));

        Assert.Equal(0, stream.Read(buffer, 0, buffer.Length));
        Assert.True(stream.ReadsClosed.IsCompletedSuccessfully);

        await stream.DisposeAsync();

        Assert.False(stream.CanRead);
        Assert.True(stream.ReadsClosed.IsCompletedSuccessfully);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicException_StoresApplicationAndTransportErrorCodes()
    {
        QuicException applicationException = new(QuicError.ConnectionAborted, 123, "application");
        Assert.Equal(QuicError.ConnectionAborted, applicationException.QuicError);
        Assert.Equal(123, applicationException.ApplicationErrorCode);
        Assert.Null(applicationException.TransportErrorCode);

        QuicException transportException = new(QuicError.TransportError, null, 0x0A, "transport");
        Assert.Equal(QuicError.TransportError, transportException.QuicError);
        Assert.Null(transportException.ApplicationErrorCode);
        Assert.Equal(0x0A, transportException.TransportErrorCode);
    }

    private sealed class TestQuicConnectionOptions : QuicConnectionOptions
    {
    }

    private static QuicConnectionRuntime CreateConnectionRuntime()
    {
        return new QuicConnectionRuntime(CreateBookkeeping());
    }

    private static QuicConnectionStreamState CreateReadableStreamBookkeeping()
    {
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
            IsServer: false,
            InitialConnectionReceiveLimit: 1024,
            InitialConnectionSendLimit: 1024,
            InitialIncomingBidirectionalStreamLimit: 1,
            InitialIncomingUnidirectionalStreamLimit: 1,
            InitialPeerBidirectionalStreamLimit: 1,
            InitialPeerUnidirectionalStreamLimit: 1,
            InitialLocalBidirectionalReceiveLimit: 1024,
            InitialPeerBidirectionalReceiveLimit: 1024,
            InitialPeerUnidirectionalReceiveLimit: 1024,
            InitialLocalBidirectionalSendLimit: 1024,
            InitialLocalUnidirectionalSendLimit: 1024,
            InitialPeerBidirectionalSendLimit: 1024));
    }

    private static QuicConnectionStreamState CreateBookkeeping()
    {
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
            IsServer: false,
            InitialConnectionReceiveLimit: 1024,
            InitialConnectionSendLimit: 1024,
            InitialIncomingBidirectionalStreamLimit: 0,
            InitialIncomingUnidirectionalStreamLimit: 0,
            InitialPeerBidirectionalStreamLimit: 0,
            InitialPeerUnidirectionalStreamLimit: 0,
            InitialLocalBidirectionalReceiveLimit: 0,
            InitialPeerBidirectionalReceiveLimit: 0,
            InitialPeerUnidirectionalReceiveLimit: 0,
            InitialLocalBidirectionalSendLimit: 0,
            InitialLocalUnidirectionalSendLimit: 0,
            InitialPeerBidirectionalSendLimit: 0));
    }
}
