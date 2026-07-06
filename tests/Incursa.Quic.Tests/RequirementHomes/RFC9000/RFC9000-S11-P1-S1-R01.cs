// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S11-P1-S1-R01">An endpoint that detects an error SHOULD signal the existence of that error to its peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S11-P1-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S11_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseConnectionCloseFrame_ParsesTransportAndApplicationVariants()
    {
        byte[] reasonPhrase = [0x6F, 0x6B];

        QuicConnectionCloseFrame transportFrame = new(QuicTransportErrorCode.ProtocolViolation, 0x02, reasonPhrase);
        byte[] transportEncoded = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(transportEncoded, out QuicConnectionCloseFrame parsedTransport, out int transportBytesConsumed));
        Assert.False(parsedTransport.IsApplicationError);
        Assert.Equal((ulong)QuicTransportErrorCode.ProtocolViolation, parsedTransport.ErrorCode);
        Assert.True(parsedTransport.HasTriggeringFrameType);
        Assert.Equal(0x02UL, parsedTransport.TriggeringFrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsedTransport.ReasonPhrase));
        Assert.Equal(transportEncoded.Length, transportBytesConsumed);

        Span<byte> transportDestination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedTransport, transportDestination, out int transportBytesWritten));
        Assert.Equal(transportEncoded.Length, transportBytesWritten);
        Assert.True(transportEncoded.AsSpan().SequenceEqual(transportDestination[..transportBytesWritten]));

        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase);
        byte[] applicationEncoded = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(applicationEncoded, out QuicConnectionCloseFrame parsedApplication, out int applicationBytesConsumed));
        Assert.True(parsedApplication.IsApplicationError);
        Assert.Equal(0x1234UL, parsedApplication.ErrorCode);
        Assert.False(parsedApplication.HasTriggeringFrameType);
        Assert.Equal((byte)0x1D, parsedApplication.FrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsedApplication.ReasonPhrase));
        Assert.Equal(applicationEncoded.Length, applicationBytesConsumed);

        Span<byte> applicationDestination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedApplication, applicationDestination, out int applicationBytesWritten));
        Assert.Equal(applicationEncoded.Length, applicationBytesWritten);
        Assert.True(applicationEncoded.AsSpan().SequenceEqual(applicationDestination[..applicationBytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseConnectionCloseFrame_RejectsTruncatedOrUnknownTypes()
    {
        QuicConnectionCloseFrame transportFrame = new(QuicTransportErrorCode.ProtocolViolation, 0x02, [0x6F, 0x6B]);
        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(encoded[..^1], out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1B], out _, out _));
    }

    [Fact]
    [Requirement("RFC9000-S11-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ConnectionCloseErrorCodeFuzz_PreservesRepresentativeTransportErrorCodes()
    {
        QuicTransportErrorCode[] errorCodes =
        [
            QuicTransportErrorCode.NoError,
            QuicTransportErrorCode.InternalError,
            QuicTransportErrorCode.FlowControlError,
            QuicTransportErrorCode.FrameEncodingError,
            QuicTransportErrorCode.ProtocolViolation,
            QuicTransportErrorCode.ApplicationError,
            QuicTransportErrorCode.AeadLimitReached,
            QuicTransportErrorCode.NoViablePath,
        ];
        Span<byte> destination = stackalloc byte[32];

        for (int index = 0; index < errorCodes.Length; index++)
        {
            QuicConnectionCloseFrame frame = new(
                errorCodes[index],
                triggeringFrameType: (ulong)(0x01 + index),
                [(byte)(0x40 + index)]);
            byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));
            Assert.False(parsed.IsApplicationError);
            Assert.Equal((byte)0x1C, parsed.FrameType);
            Assert.Equal((ulong)errorCodes[index], parsed.ErrorCode);
            Assert.Equal((ulong)(0x01 + index), parsed.TriggeringFrameType);
            Assert.Equal(encoded.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
        }
    }
}
