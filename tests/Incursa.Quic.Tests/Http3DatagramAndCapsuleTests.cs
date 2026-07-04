// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3DatagramAndCapsuleTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0001")]
    [Requirement("REQ-QUIC-RFC9297-0002")]
    [Requirement("REQ-QUIC-RFC9297-0008")]
    [Requirement("REQ-QUIC-RFC9297-0009")]
    [Requirement("REQ-QUIC-RFC9297-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramCodec_EncodesQuarterStreamIdBeforePayload()
    {
        Http3Datagram datagram = Http3Datagram.CreateForAssociatedStream(8, [0xCA, 0xFE]);

        byte[] encoded = datagram.Encode();
        Http3Datagram parsed = Http3Datagram.Parse(encoded);

        Assert.Equal(2UL, datagram.QuarterStreamId);
        Assert.Equal(8UL, datagram.AssociatedStreamId);
        Assert.Equal([0x02, 0xCA, 0xFE], encoded);
        Assert.Equal(datagram.QuarterStreamId, parsed.QuarterStreamId);
        Assert.Equal(datagram.Payload, parsed.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0012")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DatagramCodec_AllowsEmptyPayloadAfterQuarterStreamId()
    {
        Http3Datagram parsed = Http3Datagram.Parse([0x00]);

        Assert.Equal(0UL, parsed.QuarterStreamId);
        Assert.Empty(parsed.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramCodec_RejectsNonRequestStreamAssociation()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3Datagram.CreateForAssociatedStream(1, []));

        Assert.Equal(Http3ErrorCode.IdError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0010")]
    [Requirement("REQ-QUIC-RFC9297-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramCodec_RejectsOversizedQuarterStreamIdWithDatagramError()
    {
        byte[] encoded = EncodeVarint(Http3Datagram.MaximumQuarterStreamId + 1);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3Datagram.Parse(encoded));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0010")]
    [Requirement("REQ-QUIC-RFC9297-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramCodec_OversizedQuarterStreamIdMapsToH3DatagramError()
    {
        byte[] encoded = EncodeVarint(Http3Datagram.MaximumQuarterStreamId + 1);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3Datagram.Parse(encoded));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0010")]
    [Requirement("REQ-QUIC-RFC9297-0011")]
    [Requirement("REQ-QUIC-RFC9297-0012")]
    [Requirement("REQ-QUIC-RFC9297-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramCodec_ParsesLegalQuarterStreamIdWithoutDatagramError()
    {
        Http3Datagram parsed = Http3Datagram.Parse(Http3Datagram.CreateForAssociatedStream(4, []).Encode());

        Assert.Equal(1UL, parsed.QuarterStreamId);
        Assert.Empty(parsed.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0001")]
    [Requirement("REQ-QUIC-RFC9297-0008")]
    [Requirement("REQ-QUIC-RFC9297-0009")]
    [Requirement("REQ-QUIC-RFC9297-0012")]
    [Requirement("REQ-QUIC-RFC9297-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramCodec_RejectsTruncatedQuarterStreamIdWithDatagramError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3Datagram.Parse([0x40]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramCodec_TruncatedQuarterStreamIdMapsToH3DatagramError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3Datagram.Parse([0x40]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramSupport_RejectsAssociatedStreamsBeyondClientInitiatedBidirectionalLimit()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3DatagramSupport.ValidateAssociatedStreamLimit(12, 8));

        Assert.Equal(Http3ErrorCode.IdError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0003")]
    [Requirement("RFC9297-S2-1-1-P2-R01")]
    [Requirement("REQ-QUIC-RFC9297-0025")]
    [Requirement("REQ-QUIC-RFC9297-0076")]
    [Requirement("REQ-QUIC-RFC9297-0077")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SettingsH3Datagram_RoundTripsRegisteredSettingAndDefaultsToZero()
    {
        Http3Settings defaults = new();
        Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(
            ReadFrame(Http3SettingsWriter.WriteSettingsFrame(new Http3Settings(h3Datagram: 1))));

        Assert.Equal(0x33L, (long)Http3SettingIdentifier.H3Datagram);
        Assert.Equal(Http3DatagramSupport.DefaultSettingsH3DatagramValue, defaults.H3Datagram);
        Assert.Equal(1UL, frame.Values.H3Datagram);
        Assert.Contains(frame.Settings, setting => setting.Identifier == (ulong)Http3SettingIdentifier.H3Datagram && setting.Value == 1);
        Assert.DoesNotContain(
            Assert.IsType<Http3SettingsFrame>(ReadFrame(Http3SettingsWriter.WriteSettingsFrame(defaults))).Settings,
            setting => setting.Identifier == (ulong)Http3SettingIdentifier.H3Datagram);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0003")]
    [Requirement("RFC9297-S2-1-1-P2-R01")]
    [Requirement("RFC9297-S2-1-1-P2-S2-R01")]
    [Requirement("REQ-QUIC-RFC9297-0025")]
    [Requirement("REQ-QUIC-RFC9297-0076")]
    [Requirement("REQ-QUIC-RFC9297-0077")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SettingsH3Datagram_RejectsInvalidValuesWithSettingsError()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, [0x33, 0x02]);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadFrame(encoded));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P2-R01")]
    [Requirement("RFC9297-S2-1-1-P2-S2-R01")]
    [Requirement("REQ-QUIC-RFC9297-0025")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SettingsH3Datagram_InvalidValuesMapToSettingsError()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, [0x33, 0x02]);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadFrame(encoded));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramSupport_GatesSendingOnLocalAndPeerSettings()
    {
        Assert.True(Http3DatagramSupport.CanSendDatagram(new Http3Settings(h3Datagram: 1), new Http3Settings(h3Datagram: 1)));
        Assert.False(Http3DatagramSupport.CanSendDatagram(new Http3Settings(h3Datagram: 1), new Http3Settings()));
        Assert.False(Http3DatagramSupport.CanSendDatagram(new Http3Settings(), new Http3Settings(h3Datagram: 1)));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramSupport_DoesNotSendWhenEitherEndpointDisablesDatagrams()
    {
        Assert.False(Http3DatagramSupport.CanSendDatagram(new Http3Settings(h3Datagram: 1), new Http3Settings()));
        Assert.False(Http3DatagramSupport.CanSendDatagram(new Http3Settings(), new Http3Settings(h3Datagram: 1)));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P4-R01")]
    [Requirement("RFC9297-S2-1-1-P4-S2-R01")]
    [Requirement("REQ-QUIC-RFC9297-0024")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramSupport_AcceptsNondecreasingZeroRttSettings()
    {
        Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 0, acceptedSettingsH3Datagram: 0);
        Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 0, acceptedSettingsH3Datagram: 1);
        Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 1, acceptedSettingsH3Datagram: 1);
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P4-S2-R01")]
    [Requirement("RFC9297-S2-1-1-P4-S3-R02")]
    [Requirement("REQ-QUIC-RFC9297-0024")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramSupport_RejectsLoweredZeroRttSettings()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 1, acceptedSettingsH3Datagram: 0));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P4-S2-R01")]
    [Requirement("RFC9297-S2-1-1-P4-S3-R02")]
    [Requirement("REQ-QUIC-RFC9297-0024")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramSupport_LoweredZeroRttSettingsMapToSettingsError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 1, acceptedSettingsH3Datagram: 0));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0078")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ErrorCode_UsesRegisteredH3DatagramErrorValue()
    {
        Assert.Equal(0x33L, (long)Http3ErrorCode.DatagramError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0078")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ErrorCode_DistinguishesH3DatagramErrorFromSettingsError()
    {
        Assert.NotEqual(Http3ErrorCode.SettingsError, Http3ErrorCode.DatagramError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0001")]
    [Requirement("REQ-QUIC-RFC9297-0028")]
    [Requirement("REQ-QUIC-RFC9297-0029")]
    [Requirement("REQ-QUIC-RFC9297-0030")]
    [Requirement("REQ-QUIC-RFC9297-0031")]
    [Requirement("REQ-QUIC-RFC9297-0032")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleCodec_EncodesTypeLengthValueWithVariableLengthIntegers()
    {
        Http3Capsule capsule = new(0x40, [0xAA, 0xBB]);

        byte[] encoded = capsule.Encode();
        Http3Capsule parsed = Assert.Single(Http3Capsule.ParseSequence(encoded));

        Assert.Equal([0x40, 0x40, 0x02, 0xAA, 0xBB], encoded);
        Assert.Equal(capsule.Type, parsed.Type);
        Assert.Equal(capsule.Payload, parsed.Payload);
        Assert.Empty(new Http3Capsule(0x01, []).Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0033")]
    [Requirement("REQ-QUIC-RFC9297-0034")]
    [Requirement("REQ-QUIC-RFC9297-0035")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleCodec_RetainsKnownCapsulesAndSilentlyDropsUnknownCapsules()
    {
        byte[] unknown = new Http3Capsule(0x21, [0x01]).Encode();
        byte[] datagram = Http3Capsule.CreateDatagram([0x02, 0xCA]).Encode();
        byte[] encoded = [.. unknown, .. datagram];

        Http3Capsule parsed = Assert.Single(Http3Capsule.ParseSequence(encoded, type => type == Http3Capsule.DatagramCapsuleType));

        Assert.Equal(Http3Capsule.DatagramCapsuleType, parsed.Type);
        Assert.Equal([0x02, 0xCA], parsed.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0028")]
    [Requirement("REQ-QUIC-RFC9297-0029")]
    [Requirement("REQ-QUIC-RFC9297-0030")]
    [Requirement("REQ-QUIC-RFC9297-0031")]
    [Requirement("REQ-QUIC-RFC9297-0032")]
    [Requirement("REQ-QUIC-RFC9297-0033")]
    [Requirement("REQ-QUIC-RFC9297-0034")]
    [Requirement("REQ-QUIC-RFC9297-0035")]
    [Requirement("RFC9297-S3-3-P1-R01")]
    [Requirement("RFC9297-S3-3-P2-S1-R01")]
    [Requirement("RFC9297-S3-3-P3-R01")]
    [Requirement("REQ-QUIC-RFC9297-0061")]
    [Requirement("REQ-QUIC-RFC9297-0062")]
    [Requirement("REQ-QUIC-RFC9297-0063")]
    [Requirement("REQ-QUIC-RFC9297-0064")]
    [Requirement("REQ-QUIC-RFC9297-0065")]
    [Requirement("REQ-QUIC-RFC9297-0084")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapsuleCodec_RejectsTruncatedCapsulesAsMalformedMessages()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3Capsule.ParseSequence([0x00, 0x02, 0xAA]));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0028")]
    [Requirement("REQ-QUIC-RFC9297-0029")]
    [Requirement("REQ-QUIC-RFC9297-0030")]
    [Requirement("REQ-QUIC-RFC9297-0031")]
    [Requirement("REQ-QUIC-RFC9297-0032")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapsuleCodec_RejectsTruncatedEntryFieldsAsMalformedMessages()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3Capsule.ParseSequence([0x00, 0x02, 0xAA]));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0033")]
    [Requirement("REQ-QUIC-RFC9297-0034")]
    [Requirement("REQ-QUIC-RFC9297-0035")]
    [Requirement("RFC9297-S3-3-P1-R01")]
    [Requirement("RFC9297-S3-3-P2-S1-R01")]
    [Requirement("RFC9297-S3-3-P3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapsuleCodec_RejectsTruncatedKnownCapsuleAsMalformedMessage()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3Capsule.ParseSequence([0x00, 0x02, 0xAA]));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("RFC9297-S3-3-P1-R01")]
    [Requirement("RFC9297-S3-3-P2-S1-R01")]
    [Requirement("RFC9297-S3-3-P3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleCodec_ParsesCompleteCapsulesWithoutMalformedMessageError()
    {
        Http3Capsule parsed = Assert.Single(Http3Capsule.ParseSequence(new Http3Capsule(0x01, [0xAA]).Encode()));

        Assert.Equal(0x01UL, parsed.Type);
        Assert.Equal([0xAA], parsed.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0061")]
    [Requirement("REQ-QUIC-RFC9297-0062")]
    [Requirement("REQ-QUIC-RFC9297-0063")]
    [Requirement("REQ-QUIC-RFC9297-0064")]
    [Requirement("REQ-QUIC-RFC9297-0065")]
    [Requirement("REQ-QUIC-RFC9297-0084")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramCapsule_RejectsTruncatedDatagramCapsuleAsMalformedMessage()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3Capsule.ParseSequence([0x00, 0x02, 0xAA]));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0061")]
    [Requirement("REQ-QUIC-RFC9297-0062")]
    [Requirement("REQ-QUIC-RFC9297-0063")]
    [Requirement("REQ-QUIC-RFC9297-0064")]
    [Requirement("REQ-QUIC-RFC9297-0065")]
    [Requirement("REQ-QUIC-RFC9297-0084")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramCapsule_UsesTypeZeroAndCarriesHttpDatagramPayloadAfterLength()
    {
        Http3Capsule capsule = Http3Capsule.CreateDatagram([0x02, 0xCA, 0xFE]);

        Assert.Equal(Http3Capsule.DatagramCapsuleType, capsule.Type);
        Assert.Equal([0x00, 0x03, 0x02, 0xCA, 0xFE], capsule.Encode());
        Assert.Empty(Http3Capsule.CreateDatagram([]).Payload);
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
