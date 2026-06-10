// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9114-S4-0001")]
public sealed class Http3LowLevelProtocolTests
{
    public static IEnumerable<object?[]> MalformedSequenceCases()
    {
        yield return Case(
            "DATA before HEADERS",
            Http3ErrorCode.FrameUnexpected,
            client => client.SendDataBeforeHeaders());

        yield return Case(
            "Two SETTINGS frames",
            Http3ErrorCode.FrameUnexpected,
            client => client.SendTwoSettingsFrames());

        yield return Case(
            "SETTINGS on request stream",
            Http3ErrorCode.FrameUnexpected,
            client => client.SendSettingsOnRequestStream());

        yield return Case(
            "HEADERS on control stream",
            Http3ErrorCode.FrameUnexpected,
            client => client.SendHeadersOnControlStream());

        yield return Case(
            "Invalid frame length",
            Http3ErrorCode.FrameError,
            client => client.SendInvalidFrameLength());

        yield return Case(
            "Unknown frame type",
            null,
            client => client.SendUnknownFrameType());

        yield return Case(
            "Reserved frame type",
            null,
            client => client.SendReservedFrameType());

        yield return Case(
            "Malformed pseudo-header order",
            Http3ErrorCode.MessageError,
            client => client.SendMalformedPseudoHeaderOrder());

        yield return Case(
            "Uppercase header field name",
            Http3ErrorCode.MessageError,
            client => client.SendUppercaseHeaderFieldName());

        yield return Case(
            "Invalid content-length",
            Http3ErrorCode.MessageError,
            client => client.SendInvalidContentLength());

        yield return Case(
            "Server-initiated bidirectional stream",
            Http3ErrorCode.StreamCreationError,
            client => client.OpenServerInitiatedBidirectionalStreamAgainstClient());

        yield return Case(
            "Duplicate control streams",
            Http3ErrorCode.StreamCreationError,
            client => client.OpenDuplicateControlStreams());

        yield return Case(
            "Client-sent PUSH_PROMISE",
            Http3ErrorCode.FrameUnexpected,
            client => client.SendClientPushPromiseOnRequestStream());

        yield return Case(
            "Unadvertised PUSH_PROMISE",
            Http3ErrorCode.IdError,
            client => client.ReceiveUnadvertisedPushPromiseFromServer());
    }

    [Theory]
    [MemberData(nameof(MalformedSequenceCases))]
    public void LowLevelMalformedSequencesProduceExpectedOutcomes(
        string caseName,
        Http3ErrorCode? expectedError,
        Action<LowLevelHttp3ProtocolTestClient> action)
    {
        LowLevelHttp3ProtocolTestClient client = new();

        if (expectedError is null)
        {
            Exception? exception = Record.Exception(() => action(client));
            Assert.Null(exception);
            return;
        }

        Http3Exception thrown = Assert.Throws<Http3Exception>(() => action(client));
        Assert.Equal(expectedError.Value, thrown.ErrorCode);
        Assert.False(string.IsNullOrWhiteSpace(caseName));
    }

    private static object?[] Case(
        string caseName,
        Http3ErrorCode? expectedError,
        Action<LowLevelHttp3ProtocolTestClient> action)
    {
        return [caseName, expectedError, action];
    }

    public sealed class LowLevelHttp3ProtocolTestClient
    {
        private const ulong RequestStreamId = 0;
        private const ulong ClientControlStreamId = 2;
        private const ulong SecondClientControlStreamId = 6;
        private const ulong ServerInitiatedBidirectionalStreamId = 1;
        private const ulong UnknownFrameType = 0x40;
        private const ulong ReservedFrameType = 0x21;

        private readonly Http3StreamDispatcher serverDispatcher = new(Http3EndpointRole.Server);
        private readonly Http3RequestMessageValidator requestValidator = new();

        internal void SendDataBeforeHeaders()
        {
            RegisterRequestStream();
            ReceiveRequestFrame(Http3FrameWriter.WriteData("x"u8));
        }

        internal void SendTwoSettingsFrames()
        {
            RegisterClientControlStream();
            ReceiveControlFrame(Http3FrameWriter.WriteSettings([]));
            ReceiveControlFrame(Http3FrameWriter.WriteSettings([]));
        }

        internal void SendSettingsOnRequestStream()
        {
            RegisterRequestStream();
            ReceiveRequestFrame(Http3FrameWriter.WriteSettings([]));
        }

        internal void SendHeadersOnControlStream()
        {
            RegisterClientControlStream();
            ReceiveControlFrame(Http3FrameWriter.WriteSettings([]));
            ReceiveControlFrame(Http3FrameWriter.WriteHeaders([0x00, 0x00]));
        }

        internal void SendInvalidFrameLength()
        {
            Http3FrameReader reader = new();
            Assert.Empty(reader.Read([0x00, 0x03, 0x01, 0x02]));
            reader.Complete();
        }

        internal void SendUnknownFrameType()
        {
            RegisterRequestStream();
            ReceiveRequestFrame(Http3FrameWriter.WriteFrame(UnknownFrameType, "ignored"u8));
        }

        internal void SendReservedFrameType()
        {
            RegisterRequestStream();
            Http3Frame frame = ReadSingleFrame(Http3FrameWriter.WriteFrame(ReservedFrameType, "grease"u8));
            Assert.True(frame.IsReserved);
            serverDispatcher.ReceiveFrame(RequestStreamId, frame);
        }

        internal void SendMalformedPseudoHeaderOrder()
        {
            RegisterRequestStream();
            requestValidator.ReceiveHeaders(
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "example.com"),
                new QPackFieldLine("x-test", "value"),
                new QPackFieldLine(":path", "/"),
            ]);
        }

        internal void SendUppercaseHeaderFieldName()
        {
            RegisterRequestStream();
            requestValidator.ReceiveHeaders(
            [
                .. CommonRequestHeaders(),
                new QPackFieldLine("X-Test", "value"),
            ]);
        }

        internal void SendInvalidContentLength()
        {
            RegisterRequestStream();
            requestValidator.ReceiveHeaders(
            [
                .. CommonRequestHeaders(),
                new QPackFieldLine("content-length", "5"),
            ]);
            requestValidator.ReceiveData(4);
            requestValidator.Complete();
        }

        internal void OpenServerInitiatedBidirectionalStreamAgainstClient()
        {
            Http3StreamDispatcher clientDispatcher = new(Http3EndpointRole.Client);
            clientDispatcher.RegisterBidirectionalStream(ServerInitiatedBidirectionalStreamId);
        }

        internal void OpenDuplicateControlStreams()
        {
            RegisterClientControlStream();
            serverDispatcher.RegisterUnidirectionalStream(SecondClientControlStreamId);
            serverDispatcher.ReceiveUnidirectionalStreamTypeBytes(SecondClientControlStreamId, [(byte)Http3StreamType.Control]);
        }

        internal void SendClientPushPromiseOnRequestStream()
        {
            RegisterRequestStream();
            ReceiveRequestFrame(Http3FrameWriter.WritePushPromise(0, [0x00]));
        }

        internal void ReceiveUnadvertisedPushPromiseFromServer()
        {
            Http3StreamDispatcher clientDispatcher = new(Http3EndpointRole.Client);
            clientDispatcher.RegisterBidirectionalStream(RequestStreamId);
            clientDispatcher.ReceiveFrame(RequestStreamId, ReadSingleFrame(Http3FrameWriter.WritePushPromise(0, [0x00])));
        }

        private void RegisterRequestStream()
        {
            serverDispatcher.RegisterBidirectionalStream(RequestStreamId);
        }

        private void RegisterClientControlStream()
        {
            serverDispatcher.RegisterUnidirectionalStream(ClientControlStreamId);
            serverDispatcher.ReceiveUnidirectionalStreamTypeBytes(ClientControlStreamId, [(byte)Http3StreamType.Control]);
        }

        private void ReceiveControlFrame(byte[] encoded)
        {
            serverDispatcher.ReceiveFrame(ClientControlStreamId, ReadSingleFrame(encoded));
        }

        private void ReceiveRequestFrame(byte[] encoded)
        {
            Http3Frame frame = ReadSingleFrame(encoded);
            serverDispatcher.ReceiveFrame(RequestStreamId, frame);
            switch (frame)
            {
                case Http3HeadersFrame:
                    requestValidator.ReceiveHeaders(CommonRequestHeaders());
                    break;
                case Http3DataFrame data:
                    requestValidator.ReceiveData(data.Length);
                    break;
            }
        }

        private static Http3Frame ReadSingleFrame(byte[] encoded)
        {
            return Assert.Single(new Http3FrameReader().Read(encoded));
        }

        private static QPackFieldLine[] CommonRequestHeaders()
        {
            return
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "example.com"),
                new QPackFieldLine(":path", "/"),
            ];
        }
    }
}
