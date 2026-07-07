// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9114-S4-0001")]
public sealed class REQ_QUIC_RFC9114_S4_0001
{
    private static readonly string[] RequiredCases =
    [
        "DATA before HEADERS",
        "Two SETTINGS frames",
        "SETTINGS on request stream",
        "HEADERS on control stream",
        "Invalid frame length",
        "Unknown frame type",
        "Reserved frame type",
        "Malformed pseudo-header order",
        "Uppercase header field name",
        "Invalid content-length",
        "Server-initiated bidirectional stream",
        "Duplicate control streams",
        "Client-sent PUSH_PROMISE",
        "Unadvertised PUSH_PROMISE",
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LowLevelMalformedSequenceTestsAreTraceLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9114.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9114-0001.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9114-0001.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9114-0001.json");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3LowLevelProtocolTests.cs");
        string docs = ReadRepositoryFile("docs/testing/http3-low-level-protocol-tests.md");

        Assert.Contains("REQ-QUIC-RFC9114-S4-0001", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9114-0001", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9114-0001", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9114-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S4-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S4-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9114-S4-0001", verification, StringComparison.Ordinal);
        Assert.Contains("SPEC-QUIC-RFC9114", gapLedger, StringComparison.Ordinal);
        Assert.Contains("trace-owned", gapLedger, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("LowLevelHttp3ProtocolTestClient", tests, StringComparison.Ordinal);
        Assert.Contains("LowLevelMalformedSequencesProduceExpectedOutcomes", tests, StringComparison.Ordinal);

        foreach (string requiredCase in RequiredCases)
        {
            Assert.Contains(requiredCase, spec, StringComparison.Ordinal);
            Assert.Contains(requiredCase, docs, StringComparison.Ordinal);
            Assert.Contains(requiredCase, tests, StringComparison.Ordinal);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Negative")]
    [Trait("Category", "Edge")]
    public void LowLevelMalformedSequenceTestsKeepUnknownAndReservedFramesNonFatal()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9114.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9114-0001.json");
        string docs = ReadRepositoryFile("docs/testing/http3-low-level-protocol-tests.md");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3LowLevelProtocolTests.cs");

        Assert.Contains("no-error ignore behavior", spec, StringComparison.Ordinal);
        Assert.Contains("Unknown frame types are expected to be ignored", architecture, StringComparison.Ordinal);
        Assert.Contains("Reserved frame types are treated as unknown/grease", architecture, StringComparison.Ordinal);
        Assert.Contains("Ignored / no HTTP/3 error", docs, StringComparison.Ordinal);
        Assert.Contains("Unknown frame type", tests, StringComparison.Ordinal);
        Assert.Contains("Reserved frame type", tests, StringComparison.Ordinal);
        Assert.Contains("null", tests, StringComparison.Ordinal);
        Assert.DoesNotContain("complete RFC 9114 support", spec, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("complete RFC 9204 support", spec, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LowLevelMalformedSequenceTestsDocumentH3iExamples()
    {
        string docs = ReadRepositoryFile("docs/testing/http3-low-level-protocol-tests.md");

        Assert.Contains("h3i", docs, StringComparison.Ordinal);
        Assert.Contains("Action::SendHeadersFrame", docs, StringComparison.Ordinal);
        Assert.Contains("Action::SendFrame", docs, StringComparison.Ordinal);
        Assert.Contains("DATA before HEADERS", docs, StringComparison.Ordinal);
        Assert.Contains("HEADERS on control stream", docs, StringComparison.Ordinal);
        Assert.Contains("Duplicate control stream", docs, StringComparison.Ordinal);
        Assert.Contains("custom tests cover the same expected outcomes", docs, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S4-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LowLevelMalformedSequencesReturnDeterministicErrorCodesOrIgnoreOutcomes()
    {
        foreach ((string Name, Action Exercise, Http3ErrorCode? ErrorCode) malformedCase in new (string, Action, Http3ErrorCode?)[]
        {
            ("DATA before HEADERS", () => new Http3RequestMessageValidator().ReceiveData(1), Http3ErrorCode.FrameUnexpected),
            ("Two SETTINGS frames", () =>
            {
                Http3StreamDispatcher dispatcher = CreateClientControlStreamDispatcher();
                dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([])));
                dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([])));
            }, Http3ErrorCode.FrameUnexpected),
            ("SETTINGS on request stream", () =>
            {
                Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
                dispatcher.RegisterBidirectionalStream(0);
                dispatcher.ReceiveFrame(0, ReadFrame(Http3FrameWriter.WriteSettings([])));
            }, Http3ErrorCode.FrameUnexpected),
            ("HEADERS on control stream", () =>
            {
                Http3StreamDispatcher dispatcher = CreateClientControlStreamDispatcher();
                dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteHeaders([0x00])));
            }, Http3ErrorCode.FrameUnexpected),
            ("Invalid frame length", () => ReadFrame(Convert.FromHexString("03020102")), Http3ErrorCode.FrameError),
            ("Malformed pseudo-header order", () => Http3HeaderValidator.ValidateRequestHeaders(
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine("accept", "*/*"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "example.com"),
                new QPackFieldLine(":path", "/"),
            ]), Http3ErrorCode.MessageError),
            ("Uppercase header field name", () => Http3HeaderValidator.ValidateRequestHeaders(
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "example.com"),
                new QPackFieldLine(":path", "/"),
                new QPackFieldLine("Host", "example.com"),
            ]), Http3ErrorCode.MessageError),
            ("Invalid content-length", () => Http3HeaderValidator.ValidateResponseHeaders(
            [
                new QPackFieldLine(":status", "200"),
                new QPackFieldLine("content-length", "5"),
            ], receivedDataLength: 4), Http3ErrorCode.MessageError),
            ("Server-initiated bidirectional stream", () => new Http3StreamDispatcher(Http3EndpointRole.Client).RegisterBidirectionalStream(1), Http3ErrorCode.StreamCreationError),
            ("Duplicate control streams", () =>
            {
                Http3StreamDispatcher dispatcher = CreateClientControlStreamDispatcher();
                dispatcher.RegisterUnidirectionalStream(6);
                dispatcher.ReceiveUnidirectionalStreamTypeBytes(6, [(byte)Http3StreamType.Control]);
            }, Http3ErrorCode.StreamCreationError),
            ("Client-sent PUSH_PROMISE", () =>
            {
                Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
                dispatcher.RegisterBidirectionalStream(0);
                dispatcher.ReceiveFrame(0, ReadFrame(Http3FrameWriter.WritePushPromise(0, [0x00])));
            }, Http3ErrorCode.FrameUnexpected),
            ("Unadvertised PUSH_PROMISE", () =>
            {
                Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Client);
                dispatcher.RegisterBidirectionalStream(0);
                dispatcher.ReceiveFrame(0, ReadFrame(Http3FrameWriter.WritePushPromise(0, [0x00])));
            }, Http3ErrorCode.IdError),
            ("Unknown frame type", () => AssertUnknownFrame(0x41, isReserved: false), null),
            ("Reserved frame type", () => AssertUnknownFrame(0x21, isReserved: true), null),
        })
        {
            if (malformedCase.ErrorCode is null)
            {
                malformedCase.Exercise();
                continue;
            }

            Http3Exception exception = Assert.Throws<Http3Exception>(malformedCase.Exercise);
            Assert.Equal(malformedCase.ErrorCode.Value, exception.ErrorCode);
            Assert.Contains(malformedCase.Name, RequiredCases);
        }
    }

    private static Http3StreamDispatcher CreateClientControlStreamDispatcher()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [(byte)Http3StreamType.Control]);
        return dispatcher;
    }

    private static void AssertUnknownFrame(ulong frameType, bool isReserved)
    {
        Http3UnknownFrame frame = Assert.IsType<Http3UnknownFrame>(ReadFrame(Http3FrameWriter.WriteFrame(frameType, [0xAA])));

        Assert.Equal(frameType, frame.Type);
        Assert.Equal(isReserved, frame.IsReserved);
    }

    private static Http3Frame ReadFrame(byte[] encoded)
    {
        return Assert.Single(new Http3FrameReader().Read(encoded));
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
            string testMarker = Path.Combine(current.FullName, "tests", "Incursa.Quic.Tests", "Http3LowLevelProtocolTests.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(testMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9114 low-level malformed sequence test.");
    }
}
