// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3StreamDispatcherTests
{
    [Fact]
    public void RegisterBidirectionalStream_MapsClientInitiatedStreamsToRequests()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);

        Http3StreamInfo info = dispatcher.RegisterBidirectionalStream(0);

        Assert.Equal(Http3StreamInitiator.Client, info.Initiator);
        Assert.Equal(Http3StreamDirection.Bidirectional, info.Direction);
        Assert.Equal(Http3StreamKind.Request, info.Kind);
    }

    [Fact]
    public void RegisterBidirectionalStream_RejectsServerInitiatedStreamsWhenExtensionsAreNotEnabled()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Client);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => dispatcher.RegisterBidirectionalStream(1));

        Assert.Equal(Http3ErrorCode.StreamCreationError, exception.ErrorCode);
    }

    [Fact]
    public void RegisterBidirectionalStream_AllowsServerInitiatedStreamsWhenExtensionIsEnabled()
    {
        Http3StreamDispatcher dispatcher = new(
            Http3EndpointRole.Client,
            allowServerInitiatedBidirectionalStreams: true);

        Http3StreamInfo info = dispatcher.RegisterBidirectionalStream(1);

        Assert.Equal(Http3StreamInitiator.Server, info.Initiator);
        Assert.Equal(Http3StreamKind.Request, info.Kind);
    }

    [Fact]
    public void RegisterUnidirectionalStream_ParsesStreamTypeAcrossPartialBuffers()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);

        Http3StreamInfo pending = dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x40]);
        Assert.Null(pending.StreamType);

        Http3StreamInfo info = dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x02]);

        Assert.Equal(Http3StreamKind.QPackEncoder, info.Kind);
        Assert.Equal(2UL, info.StreamType);
        Assert.Equal(Http3StreamInitiator.Client, info.Initiator);
    }

    [Theory]
    [InlineData(0UL, Http3StreamKind.Control)]
    [InlineData(2UL, Http3StreamKind.QPackEncoder)]
    [InlineData(3UL, Http3StreamKind.QPackDecoder)]
    [InlineData(0x21UL, Http3StreamKind.Reserved)]
    [InlineData(0x41UL, Http3StreamKind.Unknown)]
    public void RegisterUnidirectionalStream_MapsKnownReservedAndUnknownStreamTypes(
        ulong streamType,
        Http3StreamKind expectedKind)
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);

        Http3StreamInfo info = dispatcher.ReceiveUnidirectionalStreamTypeBytes(
            2,
            EncodeVarint(streamType));

        Assert.Equal(expectedKind, info.Kind);
        Assert.Equal(streamType, info.StreamType);
    }

    [Fact]
    public void RegisterUnidirectionalStream_RejectsMissingStreamTypeAtEndOfStream()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);

        Http3Exception exception =
            Assert.Throws<Http3Exception>(() => dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x40], endOfStream: true));

        Assert.Equal(Http3ErrorCode.StreamCreationError, exception.ErrorCode);
    }

    [Fact]
    public void RegisterUnidirectionalStream_RejectsPayloadBytesBundledWithStreamType()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);

        Http3Exception exception =
            Assert.Throws<Http3Exception>(() => dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x00, 0x04, 0x00]));

        Assert.Equal(Http3ErrorCode.StreamCreationError, exception.ErrorCode);
    }

    [Fact]
    public void ControlStream_RejectsDuplicateControlStreamsFromSameEndpoint()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x00]);
        dispatcher.RegisterUnidirectionalStream(6);

        Http3Exception exception =
            Assert.Throws<Http3Exception>(() => dispatcher.ReceiveUnidirectionalStreamTypeBytes(6, [0x00]));

        Assert.Equal(Http3ErrorCode.StreamCreationError, exception.ErrorCode);
    }

    [Fact]
    public void ControlStream_AllowsOneControlStreamPerEndpoint()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        Http3StreamInfo clientControl = dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x00]);
        dispatcher.RegisterUnidirectionalStream(3);

        Http3StreamInfo serverControl = dispatcher.ReceiveUnidirectionalStreamTypeBytes(3, [0x00]);

        Assert.Equal(Http3StreamInitiator.Client, clientControl.Initiator);
        Assert.Equal(Http3StreamInitiator.Server, serverControl.Initiator);
    }

    [Fact]
    public void ControlStream_RequiresSettingsAsFirstFrame()
    {
        Http3StreamDispatcher dispatcher = CreateDispatcherWithClientControlStream();

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, new Http3GoAwayFrame(0, [0x00])));

        Assert.Equal(Http3ErrorCode.MissingSettings, exception.ErrorCode);
    }

    [Fact]
    public void ControlStream_AcceptsSettingsAsFirstFrameAndControlFramesAfterward()
    {
        Http3StreamDispatcher dispatcher = CreateDispatcherWithClientControlStream();

        dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([])));
        dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteGoAway(0)));
    }

    [Fact]
    public void ControlStream_RejectsSecondSettingsFrame()
    {
        Http3StreamDispatcher dispatcher = CreateDispatcherWithClientControlStream();
        dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([])));

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([]))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    public void ControlStream_RejectsRequestOnlyFrames()
    {
        Http3StreamDispatcher dispatcher = CreateDispatcherWithClientControlStream();
        dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([])));

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteHeaders([0x00]))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    public void RequestStream_AcceptsDataHeadersAndPushPromiseFrames()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterBidirectionalStream(0);

        dispatcher.ReceiveFrame(0, ReadFrame(Http3FrameWriter.WriteHeaders([0x00])));
        dispatcher.ReceiveFrame(0, ReadFrame(Http3FrameWriter.WriteData([0x01])));
        dispatcher.ReceiveFrame(0, ReadFrame(Http3FrameWriter.WritePushPromise(0, [0x00])));
    }

    [Fact]
    public void RequestStream_RejectsControlFrames()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterBidirectionalStream(0);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(0, ReadFrame(Http3FrameWriter.WriteSettings([]))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    public void QPackStreams_RegisterButRejectHttp3Frames()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x02]);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteData([0x01]))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    public void PushStream_IsRejectedWhileServerPushIsDisabled()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Client);
        dispatcher.RegisterUnidirectionalStream(3);

        Http3Exception exception =
            Assert.Throws<Http3Exception>(() => dispatcher.ReceiveUnidirectionalStreamTypeBytes(3, [0x01]));

        Assert.Equal(Http3ErrorCode.IdError, exception.ErrorCode);
    }

    [Fact]
    public void PushStream_WhenEnabledAcceptsDataAndHeadersButRejectsPushPromise()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Client, enableServerPush: true);
        dispatcher.RegisterUnidirectionalStream(3);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(3, [0x01]);

        dispatcher.ReceiveFrame(3, ReadFrame(Http3FrameWriter.WriteHeaders([0x00])));
        dispatcher.ReceiveFrame(3, ReadFrame(Http3FrameWriter.WriteData([0x01])));
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(3, ReadFrame(Http3FrameWriter.WritePushPromise(0, [0x00]))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    public void UnknownAndReservedStreamsRejectHttp3FrameProcessing()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x21]);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteData([0x01]))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    private static Http3StreamDispatcher CreateDispatcherWithClientControlStream()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x00]);
        return dispatcher;
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
}
