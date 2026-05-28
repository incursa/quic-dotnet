// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0012">An immediate close MAY be used after an application protocol has arranged to close a connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2-0012")]
public sealed class REQ_QUIC_RFC9000_S10P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S10P2-0012")]
    public async Task CloseAsync_ProjectsTheRuntimeTerminalStateAfterApplicationShutdown()
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
    }

    private sealed class TestQuicConnectionOptions : QuicConnectionOptions
    {
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
