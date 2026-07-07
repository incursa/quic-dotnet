// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Reflection;
using Incursa.Quic.Qlog;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9308-S3P1-0001">Public application 0-RTT MUST remain unavailable until an application profile defines replay-safe early-data semantics.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9308-S4P1-0001">Application protocols MUST explicitly map QUIC streams to their protocol roles and message boundaries.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9308-S4P4-0001">Application send paths that become flow-control blocked MUST preserve stream state and expose blocked-credit diagnostics.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9308-S4P5-0001">Application stream-open paths that become stream-limit blocked MUST preserve stream state and expose blocked-stream diagnostics.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9308-S6-0001">Application close error codes MUST remain distinct from QUIC transport error codes.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9308-S9-0001">NAT rebinding and migration candidates MUST remain unpromoted until path validation succeeds.</workbench-requirement>
/// </workbench-requirements>
public sealed class REQ_QUIC_RFC9308_ApplicabilityHardening
{
    private const string GuidancePath = "docs/design/rfc9308-application-guidance.md";

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S3P1-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicConnectApi_DoesNotExposeApplicationZeroRttToggle()
    {
        string[] optionPropertyNames =
        [
            .. typeof(QuicClientConnectionOptions)
                .GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .Select(static property => property.Name),
        ];

        Assert.DoesNotContain(optionPropertyNames, static name => name.Contains("ZeroRtt", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(optionPropertyNames, static name => name.Contains("EarlyData", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S3P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Guidance_DistinguishesKeepAliveFromSessionResumption()
    {
        string guidance = ReadGuidance();

        Assert.Contains("Keep-Alive Versus Resumption", guidance, StringComparison.Ordinal);
        Assert.Contains("not TLS session resumption", guidance, StringComparison.Ordinal);
        Assert.Contains("do not authorize 0-RTT application data", guidance, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S4P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StreamPriority_IsLocalSchedulingOnly()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerBidirectionalStreamLimit: 1);
        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        QuicStream stream = new(state, streamId.Value);
        stream.Priority = 7;

        Assert.Equal(7, stream.Priority);
        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S11-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Guidance_DocumentsConnectionIdPrivacyBoundary()
    {
        string guidance = ReadGuidance();

        Assert.Contains("CID privacy/linkability", guidance, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("no broader timing-linkability guarantee", guidance, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S13-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Guidance_DistinguishesVersionMechanismsFromRolloutPolicy()
    {
        string guidance = ReadGuidance();

        Assert.Contains("Version negotiation", guidance, StringComparison.Ordinal);
        Assert.Contains("Deploying a new version", guidance, StringComparison.Ordinal);
        Assert.Contains("operator rollout plan", guidance, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S15-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Guidance_DistinguishesQuicDatagramFromHttpDatagramsAndMasque()
    {
        string guidance = ReadGuidance();

        Assert.Contains("RFC 9221 transport floor", guidance, StringComparison.Ordinal);
        Assert.Contains("HTTP Datagrams", guidance, StringComparison.Ordinal);
        Assert.Contains("MASQUE", guidance, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S4P4-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FlowControlBlockedWrite_DoesNotAdvanceStreamSendState()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 4,
            peerBidirectionalStreamLimit: 1,
            localBidirectionalSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame openBlockedFrame));
        Assert.Equal(default, openBlockedFrame);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 8,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, dataBlockedFrame.MaximumData);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0UL, snapshot.UniqueBytesSent);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S4P4-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FlowControlBlockedDiagnostic_MapsToQlog()
    {
        QuicDiagnosticEvent diagnosticEvent = QuicDiagnostics.FlowControlBlocked(new QuicStreamDataBlockedFrame(4, 16));

        Assert.Equal(QuicDiagnosticKind.FlowControlBlocked, diagnosticEvent.Kind);
        Assert.Equal(4UL, diagnosticEvent.StreamId);
        Assert.Equal(16UL, diagnosticEvent.Limit);

        QuicQlogDiagnosticsSink sink = new(isServer: false);
        sink.Emit(diagnosticEvent);

        QlogEventAssert.ContainsEvent(sink, "quic:flow_control_blocked");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StreamLimitBlockedOpen_DoesNotCreateAStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerBidirectionalStreamLimit: 0);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId blockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));

        Assert.Equal(default, blockedStreamId);
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);
        Assert.False(state.TryGetStreamSnapshot(0, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StreamLimitBlockedDiagnostic_MapsToQlog()
    {
        QuicDiagnosticEvent diagnosticEvent = QuicDiagnostics.StreamLimitBlocked(new QuicStreamsBlockedFrame(
            isBidirectional: true,
            maximumStreams: 0));

        Assert.Equal(QuicDiagnosticKind.StreamLimitBlocked, diagnosticEvent.Kind);
        Assert.True(diagnosticEvent.IsBidirectionalStream);
        Assert.Equal(0UL, diagnosticEvent.Limit);

        QuicQlogDiagnosticsSink sink = new(isServer: false);
        sink.Emit(diagnosticEvent);

        QlogEventAssert.ContainsEvent(sink, "quic:stream_limit_blocked");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S6-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task CloseAsync_ProjectsApplicationErrorWithoutTransportError()
    {
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnection connection = new(runtime, new TestQuicConnectionOptions());

        await connection.CloseAsync(0x9308);

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(0x9308UL, runtime.TerminalState.Value.Close.ApplicationErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.TransportErrorCode);

        await connection.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S9-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NatRebindingCandidate_RemainsUnpromotedUntilPathValidationSucceeds()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        QuicConnectionPathIdentity activePath = runtime.ActivePath.Value.Identity;
        QuicConnectionPathIdentity reboundPath = activePath with
        {
            RemotePort = activePath.RemotePort + 1,
        };

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                reboundPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(activePath, runtime.ActivePath.Value.Identity);
        Assert.True(runtime.CandidatePaths.ContainsKey(reboundPath));
        Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S3P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PublicApplicationZeroRttProfileRemainsUnavailableAcrossPublicOptions()
    {
        Type[] optionTypes =
        [
            typeof(QuicClientConnectionOptions),
            typeof(QuicServerConnectionOptions),
            typeof(Http3ClientOptions),
            typeof(Http3ServerOptions),
        ];

        foreach (Type optionType in optionTypes)
        {
            string[] publicMemberNames =
            [
                .. optionType.GetProperties(BindingFlags.Instance | BindingFlags.Public).Select(static property => property.Name),
                .. optionType.GetFields(BindingFlags.Instance | BindingFlags.Public).Select(static field => field.Name),
                .. optionType.GetMethods(BindingFlags.Instance | BindingFlags.Public).Select(static method => method.Name),
            ];

            Assert.DoesNotContain(publicMemberNames, static name => name.Contains("ZeroRtt", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(publicMemberNames, static name => name.Contains("EarlyData", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S3P2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_GuidanceKeepsKeepAliveSeparateFromResumptionAndZeroRtt()
    {
        string guidance = ReadGuidance();

        foreach (string phrase in new[]
        {
            "Keep-Alive Versus Resumption",
            "not TLS session resumption",
            "do not authorize 0-RTT application data",
        })
        {
            Assert.Contains(phrase, guidance, StringComparison.Ordinal);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S4P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ApplicationStreamMappingPreservesRolesAndMessageBoundaries()
    {
        foreach ((ulong StreamId, Http3EndpointRole Role, Http3StreamKind ExpectedKind) streamCase in new[]
        {
            (0UL, Http3EndpointRole.Server, Http3StreamKind.Request),
            (4UL, Http3EndpointRole.Server, Http3StreamKind.Request),
            (2UL, Http3EndpointRole.Server, Http3StreamKind.Control),
            (6UL, Http3EndpointRole.Server, Http3StreamKind.QPackEncoder),
            (10UL, Http3EndpointRole.Server, Http3StreamKind.QPackDecoder),
        })
        {
            Http3StreamDispatcher dispatcher = new(streamCase.Role);
            Http3StreamInfo info;
            if ((streamCase.StreamId & 0x02UL) == 0)
            {
                info = dispatcher.RegisterBidirectionalStream(streamCase.StreamId);
            }
            else
            {
                dispatcher.RegisterUnidirectionalStream(streamCase.StreamId);
                ulong streamType = streamCase.ExpectedKind switch
                {
                    Http3StreamKind.Control => (ulong)Http3StreamType.Control,
                    Http3StreamKind.QPackEncoder => (ulong)Http3StreamType.QPackEncoder,
                    Http3StreamKind.QPackDecoder => (ulong)Http3StreamType.QPackDecoder,
                    _ => throw new InvalidOperationException("Unexpected unidirectional stream kind."),
                };
                info = dispatcher.ReceiveUnidirectionalStreamTypeBytes(streamCase.StreamId, EncodeVarint(streamType));
            }

            Assert.Equal(streamCase.ExpectedKind, info.Kind);
        }

        Http3RequestMessageValidator validator = new();
        validator.ReceiveHeaders(
        [
            new QPackFieldLine(":method", "POST"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "example.com"),
            new QPackFieldLine(":path", "/upload"),
            new QPackFieldLine("content-length", "4"),
        ]);
        validator.ReceiveData(2);
        validator.ReceiveData(2);
        validator.Complete();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S4P4-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FlowControlBlockedSendPreservesStreamStateAndEmitsDiagnostics()
    {
        foreach ((ulong ConnectionLimit, ulong StreamLimit, ulong AttemptedLength) flowCase in new[]
        {
            (4UL, 16UL, 8UL),
            (8UL, 4UL, 12UL),
            (32UL, 16UL, 24UL),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: flowCase.ConnectionLimit,
                peerBidirectionalStreamLimit: 1,
                localBidirectionalSendLimit: flowCase.StreamLimit);
            Assert.True(state.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame openBlockedFrame));
            Assert.Equal(default, openBlockedFrame);

            Assert.False(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length: checked((int)flowCase.AttemptedLength),
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));

            Assert.Equal(default, errorCode);
            Assert.True(dataBlockedFrame.MaximumData != 0 || streamDataBlockedFrame.MaximumStreamData != 0);
            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(0UL, snapshot.UniqueBytesSent);

            QuicDiagnosticEvent diagnosticEvent = !streamDataBlockedFrame.Equals(default(QuicStreamDataBlockedFrame))
                ? QuicDiagnostics.FlowControlBlocked(streamDataBlockedFrame)
                : QuicDiagnostics.FlowControlBlocked(new QuicStreamDataBlockedFrame(streamId.Value, dataBlockedFrame.MaximumData));
            QuicQlogDiagnosticsSink sink = new(isServer: false);
            sink.Emit(diagnosticEvent);
            QlogEventAssert.ContainsEvent(sink, "quic:flow_control_blocked");
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamLimitBlockedOpenPreservesStateAndEmitsDiagnostics()
    {
        foreach ((bool Bidirectional, ulong Limit) streamCase in new[]
        {
            (true, 0UL),
            (false, 0UL),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                peerBidirectionalStreamLimit: streamCase.Bidirectional ? streamCase.Limit : 1,
                peerUnidirectionalStreamLimit: streamCase.Bidirectional ? 1 : streamCase.Limit);

            Assert.False(state.TryOpenLocalStream(
                streamCase.Bidirectional,
                out QuicStreamId blockedStreamId,
                out QuicStreamsBlockedFrame blockedFrame));

            Assert.Equal(default, blockedStreamId);
            Assert.Equal(streamCase.Bidirectional, blockedFrame.IsBidirectional);
            Assert.Equal(streamCase.Limit, blockedFrame.MaximumStreams);
            Assert.False(state.TryGetStreamSnapshot(0, out _));

            QuicQlogDiagnosticsSink sink = new(isServer: false);
            sink.Emit(QuicDiagnostics.StreamLimitBlocked(blockedFrame));
            QlogEventAssert.ContainsEvent(sink, "quic:stream_limit_blocked");
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S6-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_ApplicationCloseCodesStaySeparateFromTransportErrors()
    {
        foreach (ulong applicationErrorCode in new[] { 0UL, 1UL, 0x9308UL, 0xFFFF_FFFFUL })
        {
            QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnection connection = new(runtime, new TestQuicConnectionOptions());

            await connection.CloseAsync(checked((long)applicationErrorCode));

            Assert.True(runtime.TerminalState.HasValue);
            Assert.Equal(applicationErrorCode, runtime.TerminalState.Value.Close.ApplicationErrorCode);
            Assert.Null(runtime.TerminalState.Value.Close.TransportErrorCode);

            await connection.DisposeAsync();
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S9-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MigrationCandidatesRemainUnpromotedUntilPathValidationSucceeds()
    {
        foreach (int portDelta in new[] { 1, 7, 31 })
        {
            QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(runtime.ActivePath.HasValue);
            QuicConnectionPathIdentity activePath = runtime.ActivePath.Value.Identity;
            QuicConnectionPathIdentity reboundPath = activePath with
            {
                RemotePort = activePath.RemotePort + portDelta,
            };

            QuicConnectionTransitionResult candidateResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10,
                    reboundPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 10);

            Assert.True(candidateResult.StateChanged);
            Assert.Equal(activePath, runtime.ActivePath.Value.Identity);
            Assert.True(runtime.CandidatePaths.ContainsKey(reboundPath));
            Assert.DoesNotContain(candidateResult.Effects, static effect => effect is QuicConnectionPromoteActivePathEffect);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S11-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_GuidanceKeepsConnectionIdPrivacyBoundaryLimited()
    {
        string guidance = ReadGuidance();

        foreach (string phrase in new[]
        {
            "CID privacy/linkability",
            "no broader timing-linkability guarantee",
        })
        {
            Assert.Contains(phrase, guidance, StringComparison.OrdinalIgnoreCase);
        }

        Assert.DoesNotContain("eliminates timing linkability", guidance, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S13-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_GuidanceKeepsVersionMechanismsSeparateFromRolloutPolicy()
    {
        string guidance = ReadGuidance();

        foreach (string phrase in new[]
        {
            "Version negotiation",
            "Deploying a new version",
            "operator rollout plan",
        })
        {
            Assert.Contains(phrase, guidance, StringComparison.Ordinal);
        }

        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(QuicVersionNegotiation.Version1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9308-S15-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_GuidanceKeepsQuicDatagramSeparateFromHttpDatagramsAndMasque()
    {
        string guidance = ReadGuidance();

        foreach (string phrase in new[]
        {
            "RFC 9221 transport floor",
            "HTTP Datagrams",
            "CONNECT-UDP",
            "MASQUE",
        })
        {
            Assert.Contains(phrase, guidance, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("RFC 9221 implements MASQUE", guidance, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class TestQuicConnectionOptions : QuicConnectionOptions
    {
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[Http3VariableLengthInteger.MaxEncodedLength];
        Assert.True(Http3VariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }

    private static string ReadGuidance()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, GuidancePath);
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException("Could not locate RFC 9308 guidance document.", GuidancePath);
    }

    private static class QlogEventAssert
    {
        internal static void ContainsEvent(QuicQlogDiagnosticsSink sink, string name)
        {
            Assert.Contains(sink.Trace.Events, qlogEvent => string.Equals(qlogEvent.Name, name, StringComparison.Ordinal));
        }
    }
}
