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
        Assert.Contains("FrameWriter_And_Reader_RoundTripHeadersFrame", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameWriter_And_Reader_RoundTripSettingsFrame", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_ParsesHeadersAndPayloadSplitAcrossSingleByteReads", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_ParsesMultipleFramesAcrossSmallReads", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_RejectsTruncatedHeaderAtEndOfStream", frameTests, StringComparison.Ordinal);
        Assert.Contains("FrameReader_RejectsTruncatedPayloadAtEndOfStream", frameTests, StringComparison.Ordinal);
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
        Assert.Contains("RegisterUnidirectionalStream_MapsKnownReservedAndUnknownStreamTypes", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_RejectsDuplicateControlStreamsFromSameEndpoint", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("ControlStream_RequiresSettingsAsFirstFrame", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RequestStream_RejectsControlFrames", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RequestStream_ServerEndpointRejectsClientPushPromise", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("RequestStream_ClientEndpointRejectsPushPromiseUntilPushIsEnabled", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("QPackStreams_RegisterButRejectHttp3Frames", dispatcherTests, StringComparison.Ordinal);
        Assert.Contains("PushStream_IsRejectedWhileServerPushIsDisabled", dispatcherTests, StringComparison.Ordinal);
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
        Assert.Contains("SettingsParser_IgnoresUnknownSettings", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsParser_RejectsDuplicateSettings", settingsTests, StringComparison.Ordinal);
        Assert.Contains("SettingsParser_RejectsReservedHttp2Settings", settingsTests, StringComparison.Ordinal);
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
        Assert.Contains("GetAsync_StaticRoute_ReturnsSuccess", serverTests, StringComparison.Ordinal);
        Assert.Contains("DynamicQpackRequest_UsesPeerEncoderStreamAndReturnsSuccess", serverTests, StringComparison.Ordinal);
        Assert.Contains("InMemoryRouteHandler_MissingGet_Returns404", serverTests, StringComparison.Ordinal);
        Assert.Contains("MalformedRequestHeaders_Returns400", serverTests, StringComparison.Ordinal);
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
        Assert.Contains("CompleteResponseOnContentLength = true", clientTests, StringComparison.Ordinal);
        Assert.Contains("RepeatedLargeResponses_CompleteWithExactBodyAndFin", serverTests, StringComparison.Ordinal);
        Assert.Contains("PostDataRequest_WithOneMegabyteBody_DeliversBodyToHandler", serverTests, StringComparison.Ordinal);
        Assert.Contains("PostDataRequest_WithIncompleteContentLength_Returns400", serverTests, StringComparison.Ordinal);
        Assert.Contains("FrameReceived", serverTests, StringComparison.Ordinal);
        Assert.Contains("PayloadLength", serverTests, StringComparison.Ordinal);
        Assert.Contains("AcceptedBidirectionalStreamCanReturnResponseBytesAfterTheRequesterCompletesOnlyItsWriteSide", apiTests, StringComparison.Ordinal);
        Assert.Contains("Content-Length", verification, StringComparison.Ordinal);
        Assert.Contains("stream FIN", verification, StringComparison.Ordinal);
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
