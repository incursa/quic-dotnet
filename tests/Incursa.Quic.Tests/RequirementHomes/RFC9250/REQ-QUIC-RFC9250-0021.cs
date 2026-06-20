// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0116")]
[Requirement("REQ-QUIC-RFC9250-0117")]
[Requirement("REQ-QUIC-RFC9250-0118")]
[Requirement("REQ-QUIC-RFC9250-0119")]
[Requirement("REQ-QUIC-RFC9250-0120")]
[Requirement("REQ-QUIC-RFC9250-0121")]
[Requirement("REQ-QUIC-RFC9250-0122")]
[Requirement("REQ-QUIC-RFC9250-0123")]
public sealed class REQ_QUIC_RFC9250_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqFlowControlTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0021.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0021.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0021.json");

        Assert.Contains("ARC-QUIC-RFC9250-0021", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0021", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0021", spec, StringComparison.Ordinal);

        string[] requirementIds =
        [
            "REQ-QUIC-RFC9250-0116",
            "REQ-QUIC-RFC9250-0117",
            "REQ-QUIC-RFC9250-0118",
            "REQ-QUIC-RFC9250-0119",
            "REQ-QUIC-RFC9250-0120",
            "REQ-QUIC-RFC9250-0121",
            "REQ-QUIC-RFC9250-0122",
            "REQ-QUIC-RFC9250-0123",
        ];

        foreach (string requirementId in requirementIds)
        {
            Assert.Contains(requirementId, spec, StringComparison.Ordinal);
            Assert.Contains(requirementId, architecture, StringComparison.Ordinal);
            Assert.Contains(requirementId, workItem, StringComparison.Ordinal);
            Assert.Contains(requirementId, verification, StringComparison.Ordinal);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqFlowControlCodeAndTestsAreTraceLinked()
    {
        string streamState = ReadRepositoryFile("src/Incursa.Quic/QuicConnectionStreamState.cs");
        string runtimeProtocol = ReadRepositoryFile("src/Incursa.Quic/QuicConnectionRuntime.Protocol.cs");
        string clientHost = ReadRepositoryFile("src/Incursa.Quic/QuicClientConnectionHost.cs");
        string listenerHost = ReadRepositoryFile("src/Incursa.Quic/QuicListenerHost.cs");
        string zeroRttPolicy = ReadRepositoryFile("src/Incursa.Quic/QuicZeroRttTransportParameterPolicy.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/RequirementHomes/RFC9250/REQ-QUIC-RFC9250-0021.cs");

        Assert.Contains("TryReceiveStreamFrame(", streamState, StringComparison.Ordinal);
        Assert.Contains("TryApplyInitialReceiveLimits(", streamState, StringComparison.Ordinal);
        Assert.Contains("TryOpenLocalStream(", streamState, StringComparison.Ordinal);
        Assert.Contains("FlowControlError", streamState, StringComparison.Ordinal);
        Assert.Contains("StreamLimitError", streamState, StringComparison.Ordinal);
        Assert.Contains("InitialMaxData = (ulong)Math.Max(0, receiveWindowSizes.Connection)", clientHost, StringComparison.Ordinal);
        Assert.Contains("InitialMaxStreamDataBidiLocal = (ulong)Math.Max(0, receiveWindowSizes.LocallyInitiatedBidirectionalStream)", clientHost, StringComparison.Ordinal);
        Assert.Contains("InitialMaxStreamDataBidiRemote = (ulong)Math.Max(0, receiveWindowSizes.RemotelyInitiatedBidirectionalStream)", clientHost, StringComparison.Ordinal);
        Assert.Contains("InitialMaxStreamsBidi = (ulong)Math.Max(0, options.MaxInboundBidirectionalStreams)", clientHost, StringComparison.Ordinal);
        Assert.Contains("InitialMaxStreamsUni = (ulong)Math.Max(0, options.MaxInboundUnidirectionalStreams)", clientHost, StringComparison.Ordinal);
        Assert.Contains("InitialMaxData = (ulong)Math.Max(0, receiveWindowSizes.Connection)", listenerHost, StringComparison.Ordinal);
        Assert.Contains("ApplyReturnedInitialReceiveLimits(runtime, selectedOptions)", listenerHost, StringComparison.Ordinal);
        Assert.Contains("TryApplyPeerInitialMaxData(", runtimeProtocol, StringComparison.Ordinal);
        Assert.Contains("TryApplyPeerTransportParameterSendLimits(", runtimeProtocol, StringComparison.Ordinal);
        Assert.Contains("TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true", runtimeProtocol, StringComparison.Ordinal);
        Assert.Contains("TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false", runtimeProtocol, StringComparison.Ordinal);
        Assert.Contains("CreateRememberedTransportParametersForClientZeroRtt", zeroRttPolicy, StringComparison.Ordinal);
        Assert.Contains("EvaluateServerZeroRttAcceptance", zeroRttPolicy, StringComparison.Ordinal);
        Assert.Contains("ConnectionAndPerStreamReceiveLimitsRejectOverflow", tests, StringComparison.Ordinal);
        Assert.Contains("ReturnedServerReceiveWindowsUpdateRuntimeStreamReceiveLimits", tests, StringComparison.Ordinal);
        Assert.Contains("StreamCreationLimitsAreEnforced", tests, StringComparison.Ordinal);
        Assert.Contains("PeerTransportParameterCommitAppliesFlowControlLimitsToRuntimeBookkeeping", tests, StringComparison.Ordinal);
        Assert.Contains("TransportParametersRoundTripFlowControlLimits", tests, StringComparison.Ordinal);
        Assert.Contains("ZeroRttRemembersInitialFlowControlLimits", tests, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionAndPerStreamReceiveLimitsRejectOverflow()
    {
        QuicConnectionStreamState connectionLimitedState = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: 3,
            peerBidirectionalReceiveLimit: 2);

        Assert.True(TryParseStreamFrame(0x0A, 0, [0x10, 0x11], out QuicStreamFrame firstFrame));
        Assert.True(connectionLimitedState.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, connectionLimitedState.ConnectionAccountedBytesReceived);

        Assert.True(TryParseStreamFrame(0x0A, 4, [0x12, 0x13], out QuicStreamFrame secondFrame));
        Assert.False(connectionLimitedState.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        Assert.Equal(2UL, connectionLimitedState.ConnectionAccountedBytesReceived);

        QuicConnectionStreamState perStreamLimitedState = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: 10,
            peerBidirectionalReceiveLimit: 1);

        Assert.True(TryParseStreamFrame(0x0A, 0, [0x20, 0x21], out QuicStreamFrame overLimitFrame));
        Assert.False(perStreamLimitedState.TryReceiveStreamFrame(overLimitFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        Assert.Equal(0UL, perStreamLimitedState.ConnectionAccountedBytesReceived);

        QuicConnectionStreamState clientReceiveState = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: false,
            connectionReceiveLimit: 10,
            localBidirectionalReceiveLimit: 1,
            peerBidirectionalStreamLimit: 1);

        Assert.True(clientReceiveState.TryOpenLocalStream(true, out QuicStreamId localStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(TryParseStreamFrame(0x0A, localStreamId.Value, [0x30, 0x31], out QuicStreamFrame localOverLimitFrame));
        Assert.False(clientReceiveState.TryReceiveStreamFrame(localOverLimitFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReturnedServerReceiveWindowsUpdateRuntimeStreamReceiveLimits()
    {
        const ulong DefaultStreamReceiveLimit = 64 * 1024;
        const ulong RawLabStreamReceiveLimit = 16 * 1024 * 1024;

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            connectionReceiveLimit: DefaultStreamReceiveLimit,
            peerBidirectionalReceiveLimit: DefaultStreamReceiveLimit);

        Assert.True(TryParseStreamFrame(
            0x0E,
            streamId: 0,
            [0x42],
            out QuicStreamFrame frame,
            offset: DefaultStreamReceiveLimit + 1));

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);

        Assert.True(state.TryApplyInitialReceiveLimits(
            connectionReceiveLimit: RawLabStreamReceiveLimit,
            localBidirectionalReceiveLimit: DefaultStreamReceiveLimit,
            peerBidirectionalReceiveLimit: RawLabStreamReceiveLimit,
            peerUnidirectionalReceiveLimit: RawLabStreamReceiveLimit));

        Assert.True(state.TryReceiveStreamFrame(frame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(frame.StreamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(RawLabStreamReceiveLimit, snapshot.ReceiveLimit);
        Assert.Equal(1UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StreamCreationLimitsAreEnforced()
    {
        QuicConnectionStreamState outgoingState = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 1,
            peerUnidirectionalStreamLimit: 1);

        Assert.True(outgoingState.TryOpenLocalStream(true, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(0UL, firstStreamId.Value);
        Assert.Equal(default, blockedFrame);

        Assert.False(outgoingState.TryOpenLocalStream(true, out _, out blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);

        QuicConnectionStreamState incomingState = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            incomingBidirectionalStreamLimit: 1);

        Assert.True(TryParseStreamFrame(0x0A, 0, [0x40], out QuicStreamFrame firstIncomingFrame));
        Assert.True(incomingState.TryReceiveStreamFrame(firstIncomingFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(TryParseStreamFrame(0x0A, 4, [0x41], out QuicStreamFrame secondIncomingFrame));
        Assert.False(incomingState.TryReceiveStreamFrame(secondIncomingFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerTransportParameterCommitAppliesFlowControlLimitsToRuntimeBookkeeping()
    {
        QuicConnectionRuntime runtime = QuicS7P3ConnectionIdBindingTestSupport.CreateClientRuntimeForPeerTransportParameterCommit();

        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = [],
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 1024,
            InitialMaxStreamDataBidiRemote = 2048,
            InitialMaxStreamDataUni = 512,
            InitialMaxStreamsBidi = 6,
            InitialMaxStreamsUni = 5,
        };

        QuicConnectionTransitionResult result =
            QuicS7P3ConnectionIdBindingTestSupport.CommitPeerTransportParametersThroughClientRuntime(
                runtime,
                peerParameters);

        Assert.True(result.StateChanged);
        Assert.Null(runtime.TerminalState);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);

        QuicConnectionStreamState bookkeeping = runtime.StreamRegistry.Bookkeeping;
        Assert.Equal(4096UL, bookkeeping.ConnectionSendLimit);
        Assert.Equal(6UL, bookkeeping.PeerBidirectionalStreamLimit);
        Assert.Equal(5UL, bookkeeping.PeerUnidirectionalStreamLimit);

        Assert.True(bookkeeping.TryOpenLocalStream(true, out QuicStreamId bidirectionalStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.True(bookkeeping.TryGetStreamSnapshot(bidirectionalStreamId.Value, out QuicConnectionStreamSnapshot bidirectionalSnapshot));
        Assert.Equal(2048UL, bidirectionalSnapshot.SendLimit);

        Assert.True(bookkeeping.TryOpenLocalStream(false, out QuicStreamId unidirectionalStreamId, out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.True(bookkeeping.TryGetStreamSnapshot(unidirectionalStreamId.Value, out QuicConnectionStreamSnapshot unidirectionalSnapshot));
        Assert.Equal(512UL, unidirectionalSnapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportParametersRoundTripFlowControlLimits()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 1024,
            InitialMaxStreamDataBidiRemote = 2048,
            InitialMaxStreamDataUni = 512,
            InitialMaxStreamsBidi = 3,
            InitialMaxStreamsUni = 2,
        };

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedParameters));

        Assert.Equal(parameters.InitialMaxData, parsedParameters.InitialMaxData);
        Assert.Equal(parameters.InitialMaxStreamDataBidiLocal, parsedParameters.InitialMaxStreamDataBidiLocal);
        Assert.Equal(parameters.InitialMaxStreamDataBidiRemote, parsedParameters.InitialMaxStreamDataBidiRemote);
        Assert.Equal(parameters.InitialMaxStreamDataUni, parsedParameters.InitialMaxStreamDataUni);
        Assert.Equal(parameters.InitialMaxStreamsBidi, parsedParameters.InitialMaxStreamsBidi);
        Assert.Equal(parameters.InitialMaxStreamsUni, parsedParameters.InitialMaxStreamsUni);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttRemembersInitialFlowControlLimits()
    {
        QuicTransportParameters currentParameters = new()
        {
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 1024,
            InitialMaxStreamDataBidiRemote = 2048,
            InitialMaxStreamDataUni = 512,
            InitialMaxStreamsBidi = 3,
            InitialMaxStreamsUni = 2,
        };

        QuicTransportParameters? rememberedParameters =
            QuicZeroRttTransportParameterPolicy.CreateRememberedTransportParametersForClientZeroRtt(currentParameters);

        Assert.NotNull(rememberedParameters);
        Assert.Equal(currentParameters.InitialMaxData, rememberedParameters!.InitialMaxData);
        Assert.Equal(currentParameters.InitialMaxStreamDataBidiLocal, rememberedParameters.InitialMaxStreamDataBidiLocal);
        Assert.Equal(currentParameters.InitialMaxStreamDataBidiRemote, rememberedParameters.InitialMaxStreamDataBidiRemote);
        Assert.Equal(currentParameters.InitialMaxStreamDataUni, rememberedParameters.InitialMaxStreamDataUni);
        Assert.Equal(currentParameters.InitialMaxStreamsBidi, rememberedParameters.InitialMaxStreamsBidi);
        Assert.Equal(currentParameters.InitialMaxStreamsUni, rememberedParameters.InitialMaxStreamsUni);

        QuicZeroRttTransportParameterAcceptanceDecision accepted =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(rememberedParameters, currentParameters);
        Assert.True(accepted.CanAccept);

        QuicTransportParameters reducedParameters = new()
        {
            InitialMaxData = 2048,
            InitialMaxStreamDataBidiLocal = 1024,
            InitialMaxStreamDataBidiRemote = 2048,
            InitialMaxStreamDataUni = 512,
            InitialMaxStreamsBidi = 3,
            InitialMaxStreamsUni = 2,
        };

        QuicZeroRttTransportParameterAcceptanceDecision rejection =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(rememberedParameters, reducedParameters);

        Assert.False(rejection.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedRequiredLimit, rejection.Failure);
        Assert.Equal("initial_max_data", rejection.ParameterName);
    }

    private static bool TryParseStreamFrame(
        byte frameType,
        ulong streamId,
        ReadOnlySpan<byte> streamData,
        out QuicStreamFrame frame,
        ulong offset = 0)
    {
        return QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(frameType, streamId, streamData, offset),
            out frame);
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        string repoRoot = FindRepoRoot();
        string candidate = Path.Combine(repoRoot, relativePath);
        if (File.Exists(candidate))
        {
            return File.ReadAllText(candidate);
        }

        throw new InvalidOperationException($"Unable to locate '{relativePath}' under '{repoRoot}'.");
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string gitMarker = Path.Combine(current.FullName, ".git");
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9250.json");
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic", "QuicConnectionStreamState.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ flow-control tests.");
    }
}
