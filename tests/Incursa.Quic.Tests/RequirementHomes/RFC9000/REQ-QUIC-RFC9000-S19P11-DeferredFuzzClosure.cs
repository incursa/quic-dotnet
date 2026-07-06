// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P11_DeferredFuzzClosure
{
    private const ulong MaximumStreamLimit = 1UL << 60;

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MaxStreamsEncodingLimitFuzz_AcceptsOnlyValuesAtOrBelowTheSixtyBitLimit(bool isBidirectional)
    {
        ulong[] acceptedValues =
        [
            0,
            1,
            2,
            63,
            64,
            16_383,
            16_384,
            MaximumStreamLimit - 1,
            MaximumStreamLimit,
        ];
        Span<byte> destination = stackalloc byte[16];

        foreach (ulong maximumStreams in acceptedValues)
        {
            QuicMaxStreamsFrame frame = new(isBidirectional, maximumStreams);
            byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

            Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(
                encoded,
                out QuicMaxStreamsFrame parsed,
                out int bytesConsumed));
            Assert.Equal(frame, parsed);
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(frame, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
        }

        foreach (ulong maximumStreams in new[] { MaximumStreamLimit + 1, MaximumStreamLimit + 2 })
        {
            QuicMaxStreamsFrame invalidFrame = new(isBidirectional, maximumStreams);
            byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(invalidFrame);

            Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out _, out _));
            Assert.False(QuicFrameCodec.TryFormatMaxStreamsFrame(invalidFrame, destination, out _));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MaxStreamsLowerLimitFuzz_IgnoresStaleLowerLimitsAfterHigherValues(bool isBidirectional)
    {
        for (ulong baseLimit = 1; baseLimit <= 8; baseLimit++)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                peerBidirectionalStreamLimit: 0,
                peerUnidirectionalStreamLimit: 0);
            ulong highLimit = baseLimit + 8;

            Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(isBidirectional, highLimit)));

            for (ulong staleLimit = baseLimit; staleLimit < highLimit; staleLimit++)
            {
                Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(isBidirectional, staleLimit)));
                Assert.Equal(highLimit, isBidirectional
                    ? state.PeerBidirectionalStreamLimit
                    : state.PeerUnidirectionalStreamLimit);
            }
        }
    }
}
