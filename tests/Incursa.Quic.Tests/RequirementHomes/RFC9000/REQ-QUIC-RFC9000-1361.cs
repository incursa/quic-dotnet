// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1361")]
public sealed class REQ_QUIC_RFC9000_1361
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_ApplicationCloseOmitsTheTriggeringFrameType()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode: 0x1234, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.False(parsed.HasTriggeringFrameType);
        Assert.Equal(0UL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatConnectionCloseFrame_ApplicationCloseIsShorterThanTransportCloseWithATriggeringFrameType()
    {
        byte[] applicationClose = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode: 0, reasonPhrase: []);
        byte[] transportClose = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: 0,
            triggeringFrameType: 0x02,
            reasonPhrase: []);

        Assert.Equal(3, applicationClose.Length);
        Assert.Equal(4, transportClose.Length);
        Assert.DoesNotContain((byte)0x02, applicationClose);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryFormatConnectionCloseFrame_ApplicationCloseRoundTripsWithoutATriggeringFrameType()
    {
        (ulong errorCode, byte[] reasonPhrase)[] applicationCloseCases =
        [
            (0, []),
            (0x3F, [0x61]),
            (0x40, [0x02, 0x61, 0x70, 0x70]),
            (0x4000, [0xF0, 0x9F, 0x9A, 0xAB]),
        ];

        foreach ((ulong errorCode, byte[] reasonPhrase) in applicationCloseCases)
        {
            byte[] applicationClose = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode, reasonPhrase);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                applicationClose,
                out QuicConnectionCloseFrame parsedApplicationClose,
                out int bytesConsumed));

            byte[] formatted = new byte[applicationClose.Length];
            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(
                parsedApplicationClose,
                formatted,
                out int bytesWritten));

            Assert.True(parsedApplicationClose.IsApplicationError);
            Assert.False(parsedApplicationClose.HasTriggeringFrameType);
            Assert.Equal(0UL, parsedApplicationClose.TriggeringFrameType);
            Assert.Equal(applicationClose.Length, bytesConsumed);
            Assert.Equal(applicationClose.Length, bytesWritten);
            Assert.Equal(applicationClose, formatted);
        }
    }
}
