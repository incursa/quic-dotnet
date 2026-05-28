// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
public sealed class REQ_QUIC_RFC9000_S4P6_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerTransportParameterCommit_AcceptsInitialMaxStreamsAtTheEncodingLimit()
    {
        QuicConnectionRuntime runtime =
            QuicS7P3ConnectionIdBindingTestSupport.CreateClientRuntimeForPeerTransportParameterCommit();
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = [],
            InitialMaxStreamsBidi = 1UL << 60,
            InitialMaxStreamsUni = 1UL << 60,
        };

        QuicConnectionTransitionResult result =
            QuicS7P3ConnectionIdBindingTestSupport.CommitPeerTransportParametersThroughClientRuntime(
                runtime,
                peerParameters);

        Assert.True(result.StateChanged);
        Assert.Null(runtime.TerminalState);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.Equal(1UL << 60, runtime.StreamRegistry.Bookkeeping.PeerBidirectionalStreamLimit);
        Assert.Equal(1UL << 60, runtime.StreamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PeerTransportParameterCommit_ClosesOnOversizedInitialMaxStreams()
    {
        QuicConnectionRuntime runtime =
            QuicS7P3ConnectionIdBindingTestSupport.CreateClientRuntimeForPeerTransportParameterCommit();
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = [],
            InitialMaxStreamsBidi = (1UL << 60) + 1,
        };

        QuicConnectionTransitionResult result =
            QuicS7P3ConnectionIdBindingTestSupport.CommitPeerTransportParametersThroughClientRuntime(
                runtime,
                peerParameters);

        Assert.True(result.StateChanged);
        QuicS7P3ConnectionIdBindingTestSupport.AssertTransportParameterErrorClose(runtime);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0006">If an oversized max_streams value is received in a transport parameter, the connection MUST be closed immediately with TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatAndParseTransportParameters_RejectsInitialMaxStreamsAboveTheLimit()
    {
        QuicTransportParameters boundaryParameters = new()
        {
            InitialMaxStreamsBidi = 1UL << 60,
            InitialMaxStreamsUni = 1UL << 60,
        };

        Span<byte> boundaryDestination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            boundaryParameters,
            QuicTransportParameterRole.Server,
            boundaryDestination,
            out int boundaryBytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            boundaryDestination[..boundaryBytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters boundaryParsed));
        Assert.Equal(1UL << 60, boundaryParsed.InitialMaxStreamsBidi);
        Assert.Equal(1UL << 60, boundaryParsed.InitialMaxStreamsUni);

        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsBidi = (1UL << 60) + 1,
            InitialMaxStreamsUni = (1UL << 60) + 1,
        };

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            stackalloc byte[64],
            out _));

        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x08,
            QuicVarintTestData.EncodeMinimal((1UL << 60) + 1));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            tuple,
            QuicTransportParameterRole.Client,
            out _));
    }
}
