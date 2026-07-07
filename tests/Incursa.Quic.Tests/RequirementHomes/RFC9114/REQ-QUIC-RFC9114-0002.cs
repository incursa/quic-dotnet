// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9114-S4-0002")]
[Requirement("REQ-QUIC-RFC9114-S6-0001")]
[Requirement("REQ-QUIC-RFC9114-S7-0001")]
[Requirement("REQ-QUIC-RFC9114-S8-0001")]
[Requirement("REQ-QUIC-RFC9114-S9-0001")]
[Requirement("REQ-QUIC-RFC9114-S9-0002")]
public sealed class REQ_QUIC_RFC9114_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3CoreFloorIsTraceLinkedAcrossCanonicalArtifacts()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9114.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9114-0002.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9114-0002.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9114-0002.json");
        string http3Readme = ReadRepositoryFile("src/Incursa.Quic.Http3/README.md");
        string frameTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3FrameLayerTests.cs");
        string dispatcherTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3StreamDispatcherTests.cs");
        string settingsTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3SettingsHandlingTests.cs");
        string headerTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3HeaderValidationTests.cs");
        string clientTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3MinimalClientTests.cs");
        string serverTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3MinimalServerTests.cs");

        Assert.Contains("REQ-QUIC-RFC9114-S4-0002", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S6-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S7-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S8-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S9-0001", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9114-0002", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9114-0002", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9114-0002", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S4-0002", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S6-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S7-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S8-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S9-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S4-0002", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S6-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S7-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S8-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S9-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S4-0002", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S6-0001", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S7-0001", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S8-0001", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S9-0001", verification, StringComparison.Ordinal);
        Assert.Contains("HTTP/3 package", http3Readme, StringComparison.Ordinal);
        Assert.Contains("control-stream", http3Readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("request-stream", http3Readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SETTINGS", http3Readme, StringComparison.Ordinal);
        Assert.Contains("Http3FrameLayerTests", frameTests, StringComparison.Ordinal);
        Assert.Contains("Http3StreamDispatcherTests", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("Http3SettingsHandlingTests", settingsTests, StringComparison.Ordinal);
        Assert.Contains("Http3HeaderValidationTests", headerTests, StringComparison.Ordinal);
        Assert.Contains("Http3MinimalClientTests", clientTests, StringComparison.Ordinal);
        Assert.Contains("Http3MinimalServerTests", serverTests, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3FrameLayerTestsCoverDeterministicFrameHandling()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9114.json");
        string frameTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3FrameLayerTests.cs");

        Assert.Contains("FrameWriter_And_Reader_RoundTripDataFrame", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameWriter_DataFrameUsesExactLengthForLargePayload", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameWriter_And_Reader_RoundTripHeadersFrame", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameWriter_And_Reader_RoundTripSettingsFrame", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameWriter_And_Reader_RoundTripSingleIntegerFrames", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameWriter_And_Reader_RoundTripPushPromiseFrame", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_ReturnsUnknownFrameForUnknownType", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_ParsesHeadersAndPayloadSplitAcrossSingleByteReads", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_ParsesMultipleFramesAcrossSmallReads", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_RejectsTruncatedHeaderAtEndOfStream", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_RejectsTruncatedPayloadAtEndOfStream", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_RejectsSingleIntegerFrameWithExtraPayloadBytes", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_RejectsSettingsPayloadWithTruncatedPair", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_RejectsDuplicateSettingsIdentifiers", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_RejectsPushPromiseWithoutPushId", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_PreservesReservedFrameTypesAsUnknownFrames", frameTests, StringComparison.Ordinal);
        Assert.Contains("DATA, HEADERS, SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, and PUSH_PROMISE", spec, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3StreamDispatcherTestsCoverStreamMappingAndControlStreams()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9114.json");
        string dispatcherTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3StreamDispatcherTests.cs");

        Assert.Contains("RegisterBidirectionalStream_MapsClientInitiatedStreamsToRequests", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RegisterBidirectionalStream_RejectsServerInitiatedStreamsWhenExtensionsAreNotEnabled", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RegisterBidirectionalStream_AllowsServerInitiatedStreamsWhenExtensionIsEnabled", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RegisterUnidirectionalStream_ParsesStreamTypeAcrossPartialBuffers", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RegisterUnidirectionalStream_MapsKnownReservedAndUnknownStreamTypes", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RegisterUnidirectionalStream_RejectsMissingStreamTypeAtEndOfStream", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RegisterUnidirectionalStream_RejectsPayloadBytesBundledWithStreamType", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_RejectsDuplicateControlStreamsFromSameEndpoint", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_AllowsOneControlStreamPerEndpoint", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_RequiresSettingsAsFirstFrame", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_AcceptsSettingsAsFirstFrameAndControlFramesAfterward", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_ClientEndpointCapturesServerSettings", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_RejectsSecondSettingsFrame", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_RejectsRequestOnlyFrames", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RequestStream_AcceptsDataAndHeadersFrames", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RequestStream_RejectsControlFrames", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RequestStream_ServerEndpointRejectsClientPushPromise", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RequestStream_ClientEndpointRejectsPushPromiseUntilPushIsEnabled", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RequestStream_ClientEndpointAcceptsPushPromiseWhenPushIsEnabled", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("QPackStreams_RegisterButRejectHttp3Frames", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("PushStream_IsRejectedWhileServerPushIsDisabled", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("PushStream_WhenEnabledAcceptsDataAndHeadersButRejectsPushPromise", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("UnknownAndReservedStreamsRejectHttp3FrameProcessing", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("stream classification", spec, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3SettingsAndHeaderValidationTestsCoverRequestResponseFloor()
    {
        string settingsTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3SettingsHandlingTests.cs");
        string headerTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3HeaderValidationTests.cs");
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9114.json");

        Assert.Contains("SettingsWriter_And_Parser_RoundTripKnownSettings", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsWriter_WritesInitialControlStreamBytes", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsExchange_EmitsInitialSettingsExactlyOnceWhenTransportIsReady", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsExchange_CapturesPeerSettingsOnce", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsModel_EnforcesMaxFieldSectionSize", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsParser_IgnoresUnknownSettings", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsParser_RejectsDuplicateSettings", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsParser_RejectsReservedHttp2Settings", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsWriter_RejectsReservedHttp2Settings", settingsTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_StoresParsedPeerSettings", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsNotFirstOnControlStream_IsRejected", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsOnRequestStream_IsRejected", settingsTests, StringComparison.Ordinal);
        Assert.Contains("ValidateRequestHeaders_CommonGet_Passes", headerTests, StringComparison.Ordinal);
        Assert.Contains("ValidateResponseHeaders_CommonFinalResponse_Passes", headerTests, StringComparison.Ordinal);
        Assert.Contains("ValidateRequestHeaders_MalformedConditions_ThrowMessageError", headerTests, StringComparison.Ordinal);
        Assert.Contains("ValidateResponseHeaders_MalformedConditions_ThrowMessageError", headerTests, StringComparison.Ordinal);
        Assert.Contains("ValidateRequestHeaders_ContentLengthMustMatchDataLength", headerTests, StringComparison.Ordinal);
        Assert.Contains("ValidateResponseHeaders_ContentLengthMustMatchDataLength", headerTests, StringComparison.Ordinal);
        Assert.Contains("ValidateTrailers_RegularFieldsPassButPseudoHeadersFail", headerTests, StringComparison.Ordinal);
        Assert.Contains("RequestSequence_DataBeforeHeaders_IsFrameUnexpected", headerTests, StringComparison.Ordinal);
        Assert.Contains("RequestSequence_ContentLengthValidatedAtCompletion", headerTests, StringComparison.Ordinal);
        Assert.Contains("RequestSequence_TrailersPassWhenSupported", headerTests, StringComparison.Ordinal);
        Assert.Contains("ResponseSequence_InformationalThenFinal_Passes", headerTests, StringComparison.Ordinal);
        Assert.Contains("ResponseSequence_DataBeforeFinalResponse_IsFrameUnexpected", headerTests, StringComparison.Ordinal);
        Assert.Contains("ResponseSequence_SecondFinalResponseWithoutTrailerSupport_IsFrameUnexpected", headerTests, StringComparison.Ordinal);
        Assert.Contains("ResponseSequence_TrailersPassWhenSupported", headerTests, StringComparison.Ordinal);
        Assert.Contains("SETTINGS exchange", spec, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("header validation", spec, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3MinimalClientAndServerTestsCoverTheRequestResponseFloor()
    {
        string clientTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3MinimalClientTests.cs");
        string serverTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3MinimalServerTests.cs");
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9114.json");

        Assert.Contains("GetAsync_OverLoopbackQuic_ReturnsResponseHeadersAndBody", clientTests, StringComparison.Ordinal);
        Assert.Contains("ConnectAsync_RejectsClientOptionsWithoutH3Alpn", clientTests, StringComparison.Ordinal);
        Assert.Contains("ConnectAsync_ObservesPeerControlSettingsAndRejectsRequestsAfterGoAway", clientTests, StringComparison.Ordinal);
        Assert.Contains("GetAsync_StaticRoute_ReturnsSuccess", serverTests, StringComparison.Ordinal);
        Assert.Contains("DynamicQpackRequest_UsesPeerEncoderStreamAndReturnsSuccess", serverTests, StringComparison.Ordinal);
        Assert.Contains("InMemoryRouteHandler_MissingGet_Returns404", serverTests, StringComparison.Ordinal);
        Assert.Contains("MalformedRequestHeaders_ClosesConnectionWithMessageError", serverTests, StringComparison.Ordinal);
        Assert.Contains("GetWithoutRequestStreamFin_DispatchesAfterHeaders", serverTests, StringComparison.Ordinal);
        Assert.Contains("PeerControlStream_BundledSettingsFrame_IsObserved", serverTests, StringComparison.Ordinal);
        Assert.Contains("AbruptStreamReset_DoesNotStopLaterRequest", serverTests, StringComparison.Ordinal);
        Assert.Contains("request-response floor", spec, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3LargeBodyCompletionTestsCoverDataAccountingAndFin()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9114.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9114-0003.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9114-0003.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9114-0003.json");
        string clientTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3MinimalClientTests.cs");
        string serverTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3MinimalServerTests.cs");
        string apiTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/RequirementHomes/QUIC/REQ-QUIC-API-0010.cs");

        Assert.Contains("REQ-QUIC-RFC9114-S9-0002", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S4-0002", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S8-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S9-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-API-0010", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S9-0002", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S9-0002", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S9-0002", verification, StringComparison.Ordinal);
        Assert.Contains("GetAsync_WithExactContentLength_WaitsForStreamFinBeforeCompleting", clientTests, StringComparison.Ordinal);
        Assert.Contains("GetAsync_WithShortResponseBodyAndFin_RejectsContentLengthMismatch", clientTests, StringComparison.Ordinal);
        Assert.Contains("CompleteResponseOnContentLength = true", clientTests, StringComparison.Ordinal);
        Assert.Contains("RepeatedLargeResponses_CompleteWithExactBodyAndFin", serverTests, StringComparison.Ordinal);
        Assert.Contains("PostDataRequest_WithOneMegabyteBody_DeliversBodyToHandler", serverTests, StringComparison.Ordinal);
        Assert.Contains("PostDataRequest_WithIncompleteContentLength_ClosesConnectionWithMessageError", serverTests, StringComparison.Ordinal);
        Assert.Contains("FrameReceived", serverTests, StringComparison.Ordinal);
        Assert.Contains("PayloadLength", serverTests, StringComparison.Ordinal);
        Assert.Contains("AcceptedBidirectionalStreamCanReturnResponseBytesAfterTheRequesterCompletesOnlyItsWriteSide", apiTests, StringComparison.Ordinal);
        Assert.Contains("Content-Length", verification, StringComparison.Ordinal);
        Assert.Contains("stream FIN", verification, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S4-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3FrameCodecRoundTripsFragmentsAndRejectsMalformedBoundaries()
    {
        foreach (int payloadLength in new[] { 0, 1, 63, 64, 1024, 16_383 })
        {
            byte[] payload = Enumerable.Range(0, payloadLength).Select(static value => (byte)(value % 251)).ToArray();
            byte[] encoded = Http3FrameWriter.WriteData(payload);

            Http3DataFrame frame = Assert.IsType<Http3DataFrame>(ReadSingleFrameFragmented(encoded, Math.Max(1, payloadLength % 7)));

            Assert.Equal(payload, frame.Data.ToArray());
            Assert.Equal(Http3FrameWriter.GetFrameLength((ulong)Http3FrameType.Data, payloadLength), encoded.Length);
        }

        Http3Frame[] frames = new Http3FrameReader().Read(
        [
            .. Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(CommonRequestHeaders())),
            .. Http3FrameWriter.WriteSettings(
            [
                new Http3Setting((ulong)Http3SettingIdentifier.QPackMaxTableCapacity, 128),
                new Http3Setting((ulong)Http3SettingIdentifier.QPackBlockedStreams, 2),
            ]),
            .. Http3FrameWriter.WriteGoAway(0),
            .. Http3FrameWriter.WriteCancelPush(1),
            .. Http3FrameWriter.WriteMaxPushId(1),
            .. Http3FrameWriter.WritePushPromise(1, [0x00, 0x00, 0xC1]),
            .. Http3FrameWriter.WriteFrame(0x21, [0xAA]),
            .. Http3FrameWriter.WriteFrame(0x41, [0xBB]),
        ]);

        Assert.Collection(
            frames,
            frame => Assert.IsType<Http3HeadersFrame>(frame),
            frame => Assert.IsType<Http3SettingsFrame>(frame),
            frame => Assert.IsType<Http3GoAwayFrame>(frame),
            frame => Assert.IsType<Http3CancelPushFrame>(frame),
            frame => Assert.IsType<Http3MaxPushIdFrame>(frame),
            frame => Assert.IsType<Http3PushPromiseFrame>(frame),
            frame => Assert.True(Assert.IsType<Http3UnknownFrame>(frame).IsReserved),
            frame => Assert.False(Assert.IsType<Http3UnknownFrame>(frame).IsReserved));

        foreach (byte[] malformed in new[] { Convert.FromHexString("40"), Convert.FromHexString("00030102"), Convert.FromHexString("03020102") })
        {
            Assert.Throws<Http3Exception>(() =>
            {
                Http3FrameReader reader = new();
                _ = reader.Read(malformed);
                _ = reader.Complete();
            });
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S6-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3StreamDispatcherClassifiesControlQpackRequestAndUnknownStreams()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server, enableServerPush: true);

        Assert.Equal(Http3StreamKind.Request, dispatcher.RegisterBidirectionalStream(0).Kind);
        Assert.Equal(Http3ErrorCode.StreamCreationError, Assert.Throws<Http3Exception>(
            () => new Http3StreamDispatcher(Http3EndpointRole.Client).RegisterBidirectionalStream(1)).ErrorCode);

        foreach ((ulong StreamId, ulong StreamType, Http3StreamKind Kind) streamCase in new[]
        {
            (2UL, (ulong)Http3StreamType.Control, Http3StreamKind.Control),
            (6UL, (ulong)Http3StreamType.QPackEncoder, Http3StreamKind.QPackEncoder),
            (10UL, (ulong)Http3StreamType.QPackDecoder, Http3StreamKind.QPackDecoder),
            (14UL, 0x21UL, Http3StreamKind.Reserved),
            (18UL, 0x41UL, Http3StreamKind.Unknown),
        })
        {
            dispatcher.RegisterUnidirectionalStream(streamCase.StreamId);
            byte[] streamType = EncodeVarint(streamCase.StreamType);
            Http3StreamInfo info = streamType.Length > 1
                ? dispatcher.ReceiveUnidirectionalStreamTypeBytes(streamCase.StreamId, streamType[..1])
                : dispatcher.ReceiveUnidirectionalStreamTypeBytes(streamCase.StreamId, streamType);
            if (streamType.Length > 1)
            {
                Assert.Null(info.StreamType);
                info = dispatcher.ReceiveUnidirectionalStreamTypeBytes(streamCase.StreamId, streamType[1..]);
            }

            Assert.Equal(streamCase.Kind, info.Kind);
        }

        dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([])));
        dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteGoAway(0)));
        Assert.Equal(Http3ErrorCode.FrameUnexpected, Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(6, ReadFrame(Http3FrameWriter.WriteData([0x01])))).ErrorCode);
        Assert.Equal(Http3ErrorCode.FrameUnexpected, Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(14, ReadFrame(Http3FrameWriter.WriteData([0x01])))).ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3SettingsExchangeAcceptsKnownUnknownAndRejectsForbiddenShapes()
    {
        foreach (Http3Settings settings in new[]
        {
            new Http3Settings(),
            new Http3Settings(qpackMaxTableCapacity: 128, qpackBlockedStreams: 2),
            new Http3Settings(maxFieldSectionSize: 65_536),
        })
        {
            Http3SettingsExchange exchange = new(settings);

            Assert.True(exchange.TryWriteInitialSettings(out byte[] initialControlBytes));
            Assert.Equal((byte)Http3StreamType.Control, initialControlBytes[0]);
            Assert.False(exchange.TryWriteInitialSettings(out byte[] repeatedBytes));
            Assert.Empty(repeatedBytes);

            Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(ReadFrame(initialControlBytes[1..]));
            Http3SettingsExchange peer = new(new Http3Settings());
            peer.ReceivePeerSettings(frame);
            Assert.NotNull(peer.PeerSettings);
            Assert.Equal(settings.QPackMaxTableCapacity, peer.PeerSettings.QPackMaxTableCapacity);
            Assert.Equal(settings.QPackBlockedStreams, peer.PeerSettings.QPackBlockedStreams);
            Assert.Equal(settings.MaxFieldSectionSize, peer.PeerSettings.MaxFieldSectionSize);
            Assert.Equal(Http3ErrorCode.FrameUnexpected, Assert.Throws<Http3Exception>(() => peer.ReceivePeerSettings(frame)).ErrorCode);
        }

        Http3SettingsFrame unknownAndKnown = Assert.IsType<Http3SettingsFrame>(
            ReadFrame(Http3FrameWriter.WriteFrame(
                (ulong)Http3FrameType.Settings,
                [.. EncodeVarint(0x41), 0x00, .. EncodeVarint((ulong)Http3SettingIdentifier.MaxFieldSectionSize), .. EncodeVarint(100)])));
        Assert.Equal(100UL, unknownAndKnown.Values.MaxFieldSectionSize);
        Assert.Equal(2, unknownAndKnown.Settings.Count);

        foreach (byte[] invalidSettingsPayload in new[]
        {
            new byte[] { 0x06, 0x01, 0x06, 0x02 },
            new byte[] { 0x02, 0x00 },
            new byte[] { 0x04, 0x01 },
        })
        {
            Assert.Throws<Http3Exception>(() => ReadFrame(Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, invalidSettingsPayload)));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3HeaderAndMessageValidatorsRejectMalformedRequestResponseSequences()
    {
        QPackFieldLine[][] validRequests =
        [
            CommonRequestHeaders(),
            [
                new QPackFieldLine(":method", "CONNECT"),
                new QPackFieldLine(":authority", "example.com:443"),
            ],
        ];

        foreach (QPackFieldLine[] requestHeaders in validRequests)
        {
            byte[] encoded = QPackEncoder.EncodeFieldSection(requestHeaders);
            QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(encoded);
            Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false);

            Assert.Equal(requestHeaders, decoded);
            Assert.False(string.IsNullOrWhiteSpace(result.Method));
        }

        foreach (QPackFieldLine[] malformed in new[]
        {
            Without(CommonRequestHeaders(), ":method"),
            [new QPackFieldLine("accept", "*/*"), .. CommonRequestHeaders()],
            [.. CommonRequestHeaders(), new QPackFieldLine(":protocol", "webtransport")],
            [.. CommonRequestHeaders(), new QPackFieldLine("Connection", "close")],
            [.. CommonRequestHeaders(), new QPackFieldLine("content-length", "5"), new QPackFieldLine("content-length", "6")],
        })
        {
            Assert.Equal(Http3ErrorCode.MessageError, Assert.Throws<Http3Exception>(
                () => Http3HeaderValidator.ValidateRequestHeaders(malformed)).ErrorCode);
        }

        Http3RequestMessageValidator request = new();
        Assert.Equal(Http3ErrorCode.FrameUnexpected, Assert.Throws<Http3Exception>(() => request.ReceiveData(1)).ErrorCode);
        request.ReceiveHeaders([.. CommonRequestHeaders(), new QPackFieldLine("content-length", "3")]);
        request.ReceiveData(3);
        request.ReceiveHeaders([new QPackFieldLine("etag", "\"abc\"")], trailersSupported: true);
        request.Complete();

        Http3ResponseSequenceValidator response = new();
        Assert.False(response.ReceiveHeaders([new QPackFieldLine(":status", "103")]));
        Assert.True(response.ReceiveHeaders([new QPackFieldLine(":status", "200"), new QPackFieldLine("content-length", "5")]));
        response.ReceiveData(5);
        response.ReceiveHeaders([new QPackFieldLine("etag", "\"abc\"")], trailersSupported: true);
        response.Complete();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [Requirement("REQ-QUIC-RFC9114-S9-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_MinimalHttp3RequestResponseSurfacesPreserveRouteAndBodyAccounting()
    {
        foreach (int bodyLength in new[] { 0, 1, 65_536, 1_048_576 })
        {
            byte[] body = Enumerable.Range(0, bodyLength).Select(static value => (byte)(value % 251)).ToArray();
            Http3ServerResponse serverResponse = new(
                200,
                body,
                [
                    new QPackFieldLine("content-type", "application/octet-stream"),
                    new QPackFieldLine("content-length", bodyLength.ToString()),
                ]);
            IReadOnlyList<QPackFieldLine> responseHeaders = Http3Server.BuildResponseHeaders(serverResponse);
            byte[] encodedHeaders = Http3Server.EncodeResponseFieldSection(responseHeaders);
            byte[] responsePayload = [.. Http3FrameWriter.WriteHeaders(encodedHeaders), .. Http3FrameWriter.WriteData(body)];
            Http3Frame[] responseFrames = new Http3FrameReader().Read(responsePayload);
            Http3ResponseSequenceValidator responseValidator = new();

            foreach (Http3Frame frame in responseFrames)
            {
                switch (frame)
                {
                    case Http3HeadersFrame headersFrame:
                        Assert.True(responseValidator.ReceiveHeaders(QPackDecoder.DecodeFieldSection(headersFrame.EncodedFieldSection)));
                        break;
                    case Http3DataFrame dataFrame:
                        responseValidator.ReceiveData(checked((ulong)dataFrame.Data.Length));
                        Assert.Equal(body, dataFrame.Data.ToArray());
                        break;
                }
            }

            responseValidator.Complete();
            Assert.Equal(200, responseValidator.FinalStatusCode);
        }

        Http3InMemoryRouteHandler handler = new Http3InMemoryRouteHandler()
            .MapGetText("/hello", "hello");
        Http3Request request = new("GET", "https", "localhost", "/hello", CommonRequestHeaders());

        Http3ServerResponse routedResponse = await handler.HandleAsync(request);

        Assert.Equal(200, routedResponse.StatusCode);
        Assert.Equal("hello", System.Text.Encoding.UTF8.GetString(routedResponse.Body.Span));
    }

    private static Http3Frame ReadSingleFrameFragmented(byte[] encoded, int chunkSize)
    {
        Http3FrameReader reader = new();
        List<Http3Frame> frames = [];
        for (int offset = 0; offset < encoded.Length; offset += chunkSize)
        {
            frames.AddRange(reader.Read(encoded.AsSpan(offset, Math.Min(chunkSize, encoded.Length - offset))));
        }

        Assert.Empty(reader.Complete());
        return Assert.Single(frames);
    }

    private static Http3Frame ReadFrame(byte[] encoded)
    {
        return Assert.Single(new Http3FrameReader().Read(encoded));
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[Http3VariableLengthInteger.MaxEncodedLength];
        Assert.True(Http3VariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }

    private static QPackFieldLine[] CommonRequestHeaders()
    {
        return
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", "/hello"),
        ];
    }

    private static QPackFieldLine[] Without(QPackFieldLine[] headers, string name)
    {
        return [.. headers.Where(header => header.Name != name)];
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9114.json");
            string testMarker = Path.Combine(current.FullName, "tests", "Incursa.Quic.Tests", "Http3FrameLayerTests.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(testMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9114 HTTP/3 tests.");
    }
}
