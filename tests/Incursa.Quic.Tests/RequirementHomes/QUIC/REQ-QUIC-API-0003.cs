using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0003">The QuicConnection type MUST represent a connected QUIC session and expose the local endpoint, remote endpoint, target host name, negotiated application protocol, negotiated cipher suite, negotiated TLS protocol, remote certificate, AcceptInboundStreamAsync, OpenOutboundStreamAsync, CloseAsync, DisposeAsync, and ToString, while keeping handshake details, packet state, runtime state, and transport-helper state out of the public surface.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0003")]
public sealed class REQ_QUIC_API_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnection_ExposesTheApprovedStreamEntryMethods()
    {
        string[] methodNames = typeof(QuicConnection)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(method => !method.IsSpecialName)
            .Select(method => method.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "AcceptInboundStreamAsync",
            "CloseAsync",
            "ConnectAsync",
            "DisposeAsync",
            "OpenOutboundStreamAsync",
        }, methodNames);

        MethodInfo? acceptMethod = typeof(QuicConnection).GetMethod(
            nameof(QuicConnection.AcceptInboundStreamAsync),
            BindingFlags.Public | BindingFlags.Instance,
            [typeof(CancellationToken)]);
        Assert.NotNull(acceptMethod);
        Assert.Equal(typeof(ValueTask<QuicStream>), acceptMethod.ReturnType);

        MethodInfo? openMethod = typeof(QuicConnection).GetMethod(
            nameof(QuicConnection.OpenOutboundStreamAsync),
            BindingFlags.Public | BindingFlags.Instance,
            [typeof(QuicStreamType), typeof(CancellationToken)]);
        Assert.NotNull(openMethod);
        Assert.Equal(typeof(ValueTask<QuicStream>), openMethod.ReturnType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamEntry_RejectsBeforeEstablishment()
    {
        QuicConnection connection = CreateConnection();

        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(async () => await connection.AcceptInboundStreamAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(async () => await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional));
        }
        finally
        {
            await connection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamEntry_RejectsAfterCloseWithTerminalException()
    {
        QuicConnection connection = CreateConnection();

        try
        {
            await connection.CloseAsync(42);

            QuicException acceptException = await Assert.ThrowsAsync<QuicException>(async () => await connection.AcceptInboundStreamAsync());
            Assert.Equal(QuicError.ConnectionAborted, acceptException.QuicError);
            Assert.Equal(42, acceptException.ApplicationErrorCode);

            QuicException openException = await Assert.ThrowsAsync<QuicException>(async () => await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional));
            Assert.Equal(QuicError.ConnectionAborted, openException.QuicError);
            Assert.Equal(42, openException.ApplicationErrorCode);
        }
        finally
        {
            await connection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamEntry_RejectsAfterDisposeWithObjectDisposedException()
    {
        QuicConnection connection = CreateConnection();

        await connection.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await connection.AcceptInboundStreamAsync());
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional));
    }

    private sealed class TestQuicConnectionOptions : QuicConnectionOptions
    {
    }

    private static QuicConnection CreateConnection()
    {
        return new QuicConnection(CreateConnectionRuntime(), new TestQuicConnectionOptions());
    }

    private static QuicConnectionRuntime CreateConnectionRuntime()
    {
        return new QuicConnectionRuntime(CreateBookkeeping());
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
