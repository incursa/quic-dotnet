// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S11-1-P1-S1-R01">Errors that result in the connection being unusable, such as an obvious violation of protocol semantics or corruption of state that affects an entire connection, MUST be signaled using a CONNECTION_CLOSE frame (Section 19.19).</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S11-1-P1-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S11P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnusableConnectionErrorsAreSignaledUsingConnectionCloseFrames()
    {
        byte[] reasonPhrase = [0x6F, 0x6B];

        QuicConnectionCloseFrame transportFrame = new(QuicTransportErrorCode.ProtocolViolation, 0x02, reasonPhrase);
        byte[] transportEncoded = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.True(
            QuicFrameCodec.TryParseConnectionCloseFrame(
                transportEncoded,
                out QuicConnectionCloseFrame parsedTransport,
                out int transportBytesConsumed));
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

        Assert.True(
            QuicFrameCodec.TryParseConnectionCloseFrame(
                applicationEncoded,
                out QuicConnectionCloseFrame parsedApplication,
                out int applicationBytesConsumed));
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
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnusableConnectionErrorsRoundTripAsConnectionCloseFrames()
    {
        (bool ApplicationError, ulong ErrorCode, ulong TriggeringFrameType, byte[] ReasonPhrase)[] cases =
        [
            (false, (ulong)QuicTransportErrorCode.ProtocolViolation, 0x02, []),
            (false, (ulong)QuicTransportErrorCode.FlowControlError, 0x10, [0x66]),
            (false, (ulong)QuicTransportErrorCode.FrameEncodingError, 0x06, [0x66, 0x72]),
            (true, 0x01, 0, []),
            (true, 0x1234, 0, [0x61]),
            (true, 0x3FFF, 0, [0x61, 0x70, 0x70]),
        ];

        byte[] destination = new byte[64];
        foreach ((bool applicationError, ulong errorCode, ulong triggeringFrameType, byte[] reasonPhrase) in cases)
        {
            QuicConnectionCloseFrame frame = applicationError
                ? new QuicConnectionCloseFrame(errorCode, reasonPhrase)
                : new QuicConnectionCloseFrame(errorCode, triggeringFrameType, reasonPhrase);
            byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));

            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.Equal(applicationError, parsed.IsApplicationError);
            Assert.Equal(errorCode, parsed.ErrorCode);
            Assert.Equal(reasonPhrase, parsed.ReasonPhrase.ToArray());
            Assert.Equal(applicationError ? 0x1D : 0x1C, parsed.FrameType);
            if (!applicationError)
            {
                Assert.True(parsed.HasTriggeringFrameType);
                Assert.Equal(triggeringFrameType, parsed.TriggeringFrameType);
            }

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination.AsSpan(0, bytesWritten)));
        }
    }
}
