// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9250_FlowControl
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0116")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqUsesRfc9000FlowControlForSuccessfulStreamData()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(CreateStreamFrame(streamId: 0, length: 8), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(8UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0116")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqUsesRfc9000FlowControlToRejectExcessStreamData()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.False(state.TryReceiveStreamFrame(CreateStreamFrame(streamId: 0, length: 9), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        Assert.Equal(0UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0117")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportParametersCarryAggregateDataLimit()
    {
        QuicTransportParameters parsed = RoundTripTransportParameters(new QuicTransportParameters
        {
            InitialMaxData = 4096,
        });

        Assert.Equal(4096UL, parsed.InitialMaxData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0117")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AggregateDataLimitRejectsDataBeyondConnectionCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: 8,
            peerBidirectionalReceiveLimit: 16);

        Assert.True(state.TryReceiveStreamFrame(CreateStreamFrame(streamId: 0, length: 4), out _));
        Assert.False(state.TryReceiveStreamFrame(CreateStreamFrame(streamId: 4, length: 5), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0118")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportParametersCarryPerStreamDataLimits()
    {
        QuicTransportParameters parsed = RoundTripTransportParameters(new QuicTransportParameters
        {
            InitialMaxStreamDataBidiLocal = 1024,
            InitialMaxStreamDataBidiRemote = 2048,
            InitialMaxStreamDataUni = 512,
        });

        Assert.Equal(1024UL, parsed.InitialMaxStreamDataBidiLocal);
        Assert.Equal(2048UL, parsed.InitialMaxStreamDataBidiRemote);
        Assert.Equal(512UL, parsed.InitialMaxStreamDataUni);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0118")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PerStreamDataLimitRejectsDataBeyondStreamCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.False(state.TryReceiveStreamFrame(CreateStreamFrame(streamId: 0, length: 9), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0119")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportParametersCarryStreamCreationLimits()
    {
        QuicTransportParameters parsed = RoundTripTransportParameters(new QuicTransportParameters
        {
            InitialMaxStreamsBidi = 2,
            InitialMaxStreamsUni = 3,
        });

        Assert.Equal(2UL, parsed.InitialMaxStreamsBidi);
        Assert.Equal(3UL, parsed.InitialMaxStreamsUni);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0119")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StreamCreationLimitRejectsStreamsBeyondPeerCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            incomingBidirectionalStreamLimit: 1);

        Assert.True(state.TryReceiveStreamFrame(CreateStreamFrame(streamId: 0, length: 1), out _));
        Assert.False(state.TryReceiveStreamFrame(CreateStreamFrame(streamId: 4, length: 1), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0120")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerUsesGlobalAndPerStreamLimitsForClientData()
    {
        QuicConnectionStreamState serverState = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: 12,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(serverState.TryReceiveStreamFrame(CreateStreamFrame(streamId: 0, length: 8), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(8UL, serverState.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0120")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRejectsClientDataBeyondPerStreamLimit()
    {
        QuicConnectionStreamState serverState = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: 12,
            peerBidirectionalReceiveLimit: 8);

        Assert.False(serverState.TryReceiveStreamFrame(CreateStreamFrame(streamId: 0, length: 9), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0121")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientUsesGlobalAndPerStreamLimitsForServerData()
    {
        QuicConnectionStreamState clientState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 12,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(clientState.TryReceiveStreamFrame(CreateStreamFrame(streamId: 1, length: 8), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(8UL, clientState.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0121")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRejectsServerDataBeyondPerStreamLimit()
    {
        QuicConnectionStreamState clientState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 12,
            peerBidirectionalReceiveLimit: 8);

        Assert.False(clientState.TryReceiveStreamFrame(CreateStreamFrame(streamId: 1, length: 9), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0122")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandshakeTransportParametersCarryFlowControlLimits()
    {
        QuicTransportParameters parsed = RoundTripTransportParameters(new QuicTransportParameters
        {
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 1024,
            InitialMaxStreamDataBidiRemote = 2048,
            InitialMaxStreamDataUni = 512,
            InitialMaxStreamsBidi = 2,
            InitialMaxStreamsUni = 3,
        });

        Assert.Equal(4096UL, parsed.InitialMaxData);
        Assert.Equal(1024UL, parsed.InitialMaxStreamDataBidiLocal);
        Assert.Equal(2048UL, parsed.InitialMaxStreamDataBidiRemote);
        Assert.Equal(512UL, parsed.InitialMaxStreamDataUni);
        Assert.Equal(2UL, parsed.InitialMaxStreamsBidi);
        Assert.Equal(3UL, parsed.InitialMaxStreamsUni);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0122")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakeTransportParametersRejectInvalidStreamCreationLimit()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsBidi = (1UL << 60) + 1,
        };

        Span<byte> destination = stackalloc byte[64];
        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0123")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttAcceptsRememberedInitialFlowControlLimits()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.CreateRememberedParameters(),
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.CreateRememberedParameters());

        Assert.True(decision.CanAccept);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0123")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroRttRejectsReducedRememberedInitialFlowControlLimit()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                configureCurrent: static current => current.InitialMaxData = 999);

        Assert.False(decision.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedRequiredLimit, decision.Failure);
        Assert.Equal("initial_max_data", decision.ParameterName);
    }

    private static QuicTransportParameters RoundTripTransportParameters(QuicTransportParameters parameters)
    {
        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        return parsed;
    }

    private static QuicStreamFrame CreateStreamFrame(ulong streamId, int length)
    {
        byte[] streamData = new byte[length];
        streamData.AsSpan().Fill(0x51);
        return new QuicStreamFrame(
            frameType: 0x0a,
            streamId: new QuicStreamId(streamId),
            hasOffset: false,
            offset: 0,
            hasLength: true,
            length: (ulong)length,
            fin: false,
            streamData: streamData,
            consumedLength: length + 2);
    }
}
