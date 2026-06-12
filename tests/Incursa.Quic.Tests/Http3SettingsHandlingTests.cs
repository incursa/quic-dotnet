// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3SettingsHandlingTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SettingsWriter_And_Parser_RoundTripKnownSettings()
    {
        Http3Settings localSettings = new(
            qpackMaxTableCapacity: 4096,
            qpackBlockedStreams: 16,
            maxFieldSectionSize: 65536);

        Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(
            ReadFrame(Http3SettingsWriter.WriteSettingsFrame(localSettings)));

        Assert.Equal(4096UL, frame.Values.QPackMaxTableCapacity);
        Assert.Equal(16UL, frame.Values.QPackBlockedStreams);
        Assert.Equal(65536UL, frame.Values.MaxFieldSectionSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SettingsWriter_WritesInitialControlStreamBytes()
    {
        Http3Settings settings = new(qpackMaxTableCapacity: 128, qpackBlockedStreams: 2);

        byte[] encoded = Http3SettingsWriter.WriteInitialControlStream(settings);

        Assert.Equal(0x00, encoded[0]);
        Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(ReadFrame(encoded[1..]));
        Assert.Equal(128UL, frame.Values.QPackMaxTableCapacity);
        Assert.Equal(2UL, frame.Values.QPackBlockedStreams);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SettingsExchange_EmitsInitialSettingsExactlyOnceWhenTransportIsReady()
    {
        Http3SettingsExchange exchange = new(new Http3Settings(qpackMaxTableCapacity: 128));

        Assert.True(exchange.TryWriteInitialSettings(out byte[] first));
        Assert.Equal(0x00, first[0]);
        Assert.True(exchange.InitialSettingsWritten);
        Assert.False(exchange.TryWriteInitialSettings(out byte[] second));
        Assert.Empty(second);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SettingsExchange_CapturesPeerSettingsOnce()
    {
        Http3SettingsExchange exchange = new(new Http3Settings());
        Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(
            ReadFrame(Http3SettingsWriter.WriteSettingsFrame(new Http3Settings(qpackBlockedStreams: 4))));

        exchange.ReceivePeerSettings(frame);

        Assert.NotNull(exchange.PeerSettings);
        Assert.Equal(4UL, exchange.PeerSettings.QPackBlockedStreams);
        Http3Exception exception = Assert.Throws<Http3Exception>(() => exchange.ReceivePeerSettings(frame));
        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SettingsModel_EnforcesMaxFieldSectionSize()
    {
        Http3Settings settings = new(maxFieldSectionSize: 10);

        settings.ValidateFieldSectionSize(10);
        Http3Exception exception = Assert.Throws<Http3Exception>(() => settings.ValidateFieldSectionSize(11));

        Assert.Equal(Http3ErrorCode.ExcessiveLoad, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SettingsParser_IgnoresUnknownSettings()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, [0x41, 0x00, 0x01, 0x06, 0x40, 0x64]);

        Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(ReadFrame(encoded));

        Assert.Equal(100UL, frame.Values.MaxFieldSectionSize);
        Assert.Equal(0UL, frame.Values.QPackMaxTableCapacity);
        Assert.Equal(0UL, frame.Values.QPackBlockedStreams);
        Assert.Equal(2, frame.Settings.Count);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SettingsParser_RejectsDuplicateSettings()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, [0x06, 0x01, 0x06, 0x02]);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadFrame(encoded));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(0x00UL)]
    [InlineData(0x02UL)]
    [InlineData(0x03UL)]
    [InlineData(0x04UL)]
    [InlineData(0x05UL)]
    public void SettingsParser_RejectsReservedHttp2Settings(ulong settingIdentifier)
    {
        byte[] payload = [.. EncodeVarint(settingIdentifier), 0x00];
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, payload);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadFrame(encoded));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SettingsWriter_RejectsReservedHttp2Settings()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3FrameWriter.WriteSettings([new Http3Setting(0x02, 0)]));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ControlStream_StoresParsedPeerSettings()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x00]);
        Http3Frame settingsFrame = ReadFrame(
            Http3SettingsWriter.WriteSettingsFrame(
                new Http3Settings(qpackMaxTableCapacity: 256, qpackBlockedStreams: 3, maxFieldSectionSize: 1024)));

        dispatcher.ReceiveFrame(2, settingsFrame);

        Assert.True(dispatcher.TryGetControlStreamSettings(Http3StreamInitiator.Client, out Http3Settings? settings));
        Assert.NotNull(settings);
        Assert.Equal(256UL, settings.QPackMaxTableCapacity);
        Assert.Equal(3UL, settings.QPackBlockedStreams);
        Assert.Equal(1024UL, settings.MaxFieldSectionSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SettingsNotFirstOnControlStream_IsRejected()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x00]);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteGoAway(0))));

        Assert.Equal(Http3ErrorCode.MissingSettings, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SettingsOnRequestStream_IsRejected()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterBidirectionalStream(0);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(0, ReadFrame(Http3SettingsWriter.WriteSettingsFrame(new Http3Settings()))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
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
