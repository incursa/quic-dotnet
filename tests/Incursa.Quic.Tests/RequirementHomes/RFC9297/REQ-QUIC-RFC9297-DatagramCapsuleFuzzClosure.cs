// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9297_DatagramCapsuleFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0001_IntegerFieldsUseQuicVariableLengthIntegers()
    {
        Assert.Equal([0x40, 0x40, 0xAA], new Http3Datagram(64, [0xAA]).Encode());
        Assert.Equal([0x40, 0x40, 0x01, 0xAA], new Http3Capsule(64, [0xAA]).Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0002_HttpDatagramIsAssociatedWithRequestStream()
    {
        Assert.Equal(8UL, Http3Datagram.CreateForAssociatedStream(8, []).AssociatedStreamId);
        AssertIdError(() => Http3Datagram.CreateForAssociatedStream(1, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0003_QuicDatagramUseRequiresHttp3SettingNegotiation()
    {
        Assert.True(Http3DatagramSupport.CanSendDatagram(new Http3Settings(h3Datagram: 1), new Http3Settings(h3Datagram: 1)));
        Assert.False(Http3DatagramSupport.CanSendDatagram(new Http3Settings(h3Datagram: 1), new Http3Settings()));
        Assert.False(Http3DatagramSupport.CanSendDatagram(new Http3Settings(), new Http3Settings(h3Datagram: 1)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0008_Http3DatagramContainsQuarterStreamIdThenPayload()
    {
        Assert.Equal([0x02, 0xCA, 0xFE], Http3Datagram.CreateForAssociatedStream(8, [0xCA, 0xFE]).Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0009_QuarterStreamIdIsAssociatedStreamIdDividedByFour()
    {
        Assert.Equal(2UL, Http3Datagram.CreateForAssociatedStream(8, []).QuarterStreamId);
        Assert.Equal(12UL, new Http3Datagram(3, []).AssociatedStreamId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0010_QuarterStreamIdMustNotExceedSixtyBits()
    {
        _ = new Http3Datagram(Http3Datagram.MaximumQuarterStreamId, []);
        AssertDatagramError(() => new Http3Datagram(Http3Datagram.MaximumQuarterStreamId + 1, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0011_OversizedQuarterStreamIdIsH3DatagramError()
    {
        AssertDatagramError(() => Http3Datagram.Parse(EncodeVarint(Http3Datagram.MaximumQuarterStreamId + 1)));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-P3-4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P3_HttpDatagramPayloadMayBeEmpty()
    {
        Assert.Empty(Http3Datagram.Parse([0x00]).Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0013_TooShortDatagramPayloadIsH3DatagramError()
    {
        AssertDatagramError(() => Http3Datagram.Parse([0x40]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0017_StreamLimitFailureIsH3IdError()
    {
        Http3DatagramSupport.ValidateAssociatedStreamLimit(8, 8);
        AssertIdError(() => Http3DatagramSupport.ValidateAssociatedStreamLimit(12, 8));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P2_SettingsH3DatagramValueIsZeroOrOne()
    {
        Assert.Equal(1UL, Http3DatagramSupport.MaximumSettingsH3DatagramValue);
        AssertSettingsError(() => Http3DatagramSupport.ValidateZeroRttSettings(2, 2));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P2_InvalidSettingsH3DatagramValueTerminatesConnection()
    {
        AssertSettingsError(() => ReadFrame(Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, [0x33, 0x02])));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P3_DatagramFramesWaitForSentAndReceivedSettings()
    {
        Assert.True(Http3DatagramSupport.CanSendDatagram(new Http3Settings(h3Datagram: 1), new Http3Settings(h3Datagram: 1)));
        Assert.False(Http3DatagramSupport.CanSendDatagram(new Http3Settings(h3Datagram: 1), new Http3Settings(h3Datagram: 0)));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P4_ClientMayStoreZeroRttSettingsH3Datagram()
    {
        Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 0, acceptedSettingsH3Datagram: 1);
        Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 1, acceptedSettingsH3Datagram: 1);
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P4_ServerAcceptedZeroRttSettingMustNotDecrease()
    {
        Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 1, acceptedSettingsH3Datagram: 1);
        AssertSettingsError(() => Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 1, acceptedSettingsH3Datagram: 0));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P4_ClientValidatesNewSettingAgainstStoredValue()
    {
        Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 0, acceptedSettingsH3Datagram: 0);
        Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 0, acceptedSettingsH3Datagram: 1);
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P4-S3-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P4_FailedZeroRttValidationTerminatesConnection()
    {
        AssertSettingsError(() => Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 1, acceptedSettingsH3Datagram: 0));
    }

    [Fact]
    [Requirement("RFC9297-S2-1-1-P4-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P1P4_SettingsH3DatagramMustNotExceedOne()
    {
        AssertSettingsError(() => Http3DatagramSupport.ValidateZeroRttSettings(storedSettingsH3Datagram: 2, acceptedSettingsH3Datagram: 2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0028")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0028_CapsuleProtocolStreamContainsCapsuleEntries()
    {
        Http3Capsule parsed = Assert.Single(Http3Capsule.ParseSequence(new Http3Capsule(1, [0xAA]).Encode()));

        Assert.Equal(1UL, parsed.Type);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0029")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0029_CapsuleContainsTypeLengthValueFieldsInOrder()
    {
        Assert.Equal([0x01, 0x02, 0xAA, 0xBB], new Http3Capsule(1, [0xAA, 0xBB]).Encode());
    }

    [Fact]
    [Requirement("RFC9297-S3-2-P4-2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P2P4_CapsuleTypeIsVariableLengthInteger()
    {
        Assert.Equal([0x40, 0x40, 0x00], new Http3Capsule(64, []).Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0031")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0031_CapsuleLengthIsValueLengthAsVarint()
    {
        Assert.Equal([0x01, 0x40, 0x40, .. new byte[64]], new Http3Capsule(1, new byte[64]).Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0032")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0032_CapsuleLengthMayBeZero()
    {
        Assert.Empty(new Http3Capsule(1, []).Payload);
        Assert.Equal([0x01, 0x00], new Http3Capsule(1, []).Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0033")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0033_IntermediaryIdentifiesCapsuleProtocolByHeaderOrUpgradeToken()
    {
        Assert.True(Http3CapsuleProtocol.IsCapsuleProtocolInUse([Http3CapsuleProtocol.CreateCapsuleProtocolHeader()]));
        Assert.True(Http3CapsuleProtocol.CanProcessUnknownUpgradeToken([Http3CapsuleProtocol.CreateCapsuleProtocolHeader()]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0034")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0034_IntermediaryForwardsCapsulesWithoutModificationWhenRetained()
    {
        Http3Capsule capsule = Assert.Single(Http3Capsule.ParseSequence(new Http3Capsule(0x21, [0x01]).Encode()));

        Assert.Equal(0x21UL, capsule.Type);
        Assert.Equal([0x01], capsule.Payload);
    }

    [Fact]
    [Requirement("RFC9297-S3-2-P7-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P2P7_UnknownCapsuleTypesAreDroppedAndSkipped()
    {
        byte[] encoded = [.. new Http3Capsule(0x21, [0x01]).Encode(), .. Http3Capsule.CreateDatagram([0xAA]).Encode()];
        Http3Capsule retained = Assert.Single(Http3Capsule.ParseSequence(encoded, type => type == Http3Capsule.DatagramCapsuleType));

        Assert.Equal(Http3Capsule.DatagramCapsuleType, retained.Type);
        Assert.Equal([0xAA], retained.Payload);
    }

    [Fact]
    [Requirement("RFC9297-S3-3-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P3P1_CapsuleProcessingErrorIsMalformedMessage()
    {
        AssertMessageError(() => Http3Capsule.ParseSequence([0x00, 0x02, 0xAA]));
    }

    [Fact]
    [Requirement("RFC9297-S3-3-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P3P2_TruncatedCapsulePayloadIsMalformedMessage()
    {
        AssertMessageError(() => Http3Capsule.ParseSequence([0x00, 0x02, 0xAA]));
    }

    [Fact]
    [Requirement("RFC9297-S3-3-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P3P3_CleanlyTerminatedTruncatedLastCapsuleIsMalformedMessage()
    {
        AssertMessageError(() => Http3Capsule.ParseSequence([0x00, 0x02, 0xAA]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0061")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0061_DatagramCapsuleCarriesHttpDatagramOnStream()
    {
        Http3Capsule capsule = Http3Capsule.CreateDatagram(Http3Datagram.CreateForAssociatedStream(8, [0xAA]).Encode());

        Assert.Equal(Http3Capsule.DatagramCapsuleType, capsule.Type);
        Assert.Equal([0x02, 0xAA], capsule.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0062")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0062_DatagramCapsulePayloadFollowsLength()
    {
        Assert.Equal([0x00, 0x02, 0x02, 0xAA], Http3Capsule.CreateDatagram([0x02, 0xAA]).Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0063")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0063_DatagramCapsuleLengthFollowsType()
    {
        byte[] encoded = Http3Capsule.CreateDatagram([0x02, 0xAA]).Encode();

        Assert.Equal(0x00, encoded[0]);
        Assert.Equal(0x02, encoded[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0064")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0064_DatagramCapsuleTypeIsZero()
    {
        Assert.Equal(0UL, Http3Capsule.DatagramCapsuleType);
        Assert.Equal(0x00, Http3Capsule.CreateDatagram([0xAA]).Encode()[0]);
    }

    [Fact]
    [Requirement("RFC9297-S3-5-P3-2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P5P3_DatagramCapsulePayloadMayBeEmpty()
    {
        Assert.Equal([0x00, 0x00], Http3Capsule.CreateDatagram([]).Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0076")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0076_SettingsH3DatagramIdentifierIsThirtyThree()
    {
        Assert.Equal(0x33L, (long)Http3SettingIdentifier.H3Datagram);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0077")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0077_SettingsH3DatagramDefaultIsZero()
    {
        Assert.Equal(0UL, new Http3Settings().H3Datagram);
        Assert.Equal(0UL, Http3DatagramSupport.DefaultSettingsH3DatagramValue);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0078")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0078_H3DatagramErrorCodeIsThirtyThree()
    {
        Assert.Equal(0x33L, (long)Http3ErrorCode.DatagramError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0084")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0084_DatagramCapsuleRegisteredTypeIsZero()
    {
        Assert.Equal(0UL, Http3Capsule.DatagramCapsuleType);
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

    private static void AssertDatagramError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    private static void AssertIdError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.IdError, exception.ErrorCode);
    }

    private static void AssertMessageError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    private static void AssertSettingsError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }
}
