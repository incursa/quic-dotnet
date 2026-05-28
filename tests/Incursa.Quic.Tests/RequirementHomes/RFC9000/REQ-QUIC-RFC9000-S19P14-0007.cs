// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
public sealed class REQ_QUIC_RFC9000_S19P14_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamsBlockedFrame_PreservesTheAdvertisedStreamLimit()
    {
        ulong advertisedStreamLimit = 0x1234UL;
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(
            isBidirectional: true,
            maximumStreams: advertisedStreamLimit);

        QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(
            encoded,
            expectedIsBidirectional: true,
            expectedMaximumStreams: advertisedStreamLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamsBlockedFrame_PreservesTheMaximumPermittedAdvertisedStreamLimit()
    {
        ulong advertisedStreamLimit = QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit;
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(
            isBidirectional: false,
            maximumStreams: advertisedStreamLimit);

        QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(
            encoded,
            expectedIsBidirectional: false,
            expectedMaximumStreams: advertisedStreamLimit);
        Assert.Equal(1 + QuicVariableLengthInteger.MaxEncodedLength, encoded.Length);
        QuicS19P14StreamsBlockedFrameTestSupport.AssertFormats(
            new QuicStreamsBlockedFrame(isBidirectional: false, maximumStreams: advertisedStreamLimit),
            encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamsBlockedFrame_RejectsMissingAdvertisedStreamLimit()
    {
        byte[] encoded = [QuicS19P14StreamsBlockedFrameTestSupport.StreamsBlockedUnidirectionalFrameType];

        QuicS19P14StreamsBlockedFrameTestSupport.AssertRejects(encoded);
    }
}
