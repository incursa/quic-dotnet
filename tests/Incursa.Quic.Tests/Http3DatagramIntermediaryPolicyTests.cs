// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3DatagramIntermediaryPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0046")]
    [Requirement("REQ-QUIC-RFC9297-0074")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IntermediaryPolicy_AvoidsFullCapsuleBufferingAndAccumulation()
    {
        Assert.True(Http3DatagramIntermediaryPolicy.ShouldAvoidFullCapsuleValueBuffering);
        Assert.True(Http3DatagramIntermediaryPolicy.ShouldAvoidFullDatagramCapsuleAccumulation);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0046")]
    [Requirement("REQ-QUIC-RFC9297-0074")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IntermediaryPolicy_DoesNotRequireFullCapsuleBufferingBeforeHandling()
    {
        Assert.True(Http3DatagramIntermediaryPolicy.ShouldAvoidFullCapsuleValueBuffering);
        Assert.True(Http3DatagramIntermediaryPolicy.ShouldAvoidFullDatagramCapsuleAccumulation);
    }

    [Fact]
    [Requirement("RFC9297-S3-3-P2-R01")]
    [Requirement("REQ-QUIC-RFC9297-0050")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IntermediaryPolicy_AcceptsExactCapsulePayloadFieldsAndConsistentRedundantLength()
    {
        Http3DatagramIntermediaryPolicy.ValidateCapsulePayloadLength(declaredLength: 3, actualLength: 3, redundantLength: 3);
    }

    [Theory]
    [Requirement("RFC9297-S3-3-P2-R01")]
    [Requirement("REQ-QUIC-RFC9297-0050")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(3UL, 2UL, 2UL)]
    [InlineData(3UL, 3UL, 2UL)]
    public void IntermediaryPolicy_RejectsUnexpectedPayloadFieldsOrInconsistentRedundantLength(ulong declaredLength, ulong actualLength, ulong redundantLength)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3DatagramIntermediaryPolicy.ValidateCapsulePayloadLength(declaredLength, actualLength, redundantLength));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0066")]
    [Requirement("REQ-QUIC-RFC9297-0067")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IntermediaryPolicy_DatagramCapsulesParseWithHttpDatagramSemantics()
    {
        Http3Datagram parsed = Http3DatagramIntermediaryPolicy.ParseDatagramCapsulePayload(Http3Datagram.CreateForAssociatedStream(4, [0xAA]).Encode());

        Assert.Equal(1UL, parsed.QuarterStreamId);
        Assert.Equal([0xAA], parsed.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0066")]
    [Requirement("REQ-QUIC-RFC9297-0067")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IntermediaryPolicy_DatagramCapsulesInheritHttpDatagramParseErrors()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3DatagramIntermediaryPolicy.ParseDatagramCapsulePayload([0x40]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0068")]
    [Requirement("REQ-QUIC-RFC9297-0069")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IntermediaryPolicy_ReencodesBetweenDatagramFramesAndCapsulesWhenIdentified()
    {
        Assert.Equal(
            Http3DatagramIntermediaryAction.ReencodeAsDatagramCapsule,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, incomingDatagramFrame: true, outgoingSupportsDatagramFrames: false, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: true));
        Assert.Equal(
            Http3DatagramIntermediaryAction.ReencodeAsDatagramFrame,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, incomingDatagramFrame: false, outgoingSupportsDatagramFrames: true, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0068")]
    [Requirement("REQ-QUIC-RFC9297-0069")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IntermediaryPolicy_RefusesReencodingBeforeCapsuleProtocolIdentification()
    {
        Assert.Equal(
            Http3DatagramIntermediaryAction.RequireCapsuleProtocolIdentification,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(false, incomingDatagramFrame: true, outgoingSupportsDatagramFrames: false, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0070")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IntermediaryPolicy_ForwardsDatagramFramesWithoutCapsuleConversionWhenFramesAreSupported()
    {
        Assert.Equal(
            Http3DatagramIntermediaryAction.ForwardAsDatagramFrame,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, incomingDatagramFrame: true, outgoingSupportsDatagramFrames: true, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0070")]
    [Requirement("REQ-QUIC-RFC9297-0071")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IntermediaryPolicy_DropsOversizedDatagramsInsteadOfConvertingWhenFramesAreSupported()
    {
        Assert.Equal(
            Http3DatagramIntermediaryAction.Drop,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, incomingDatagramFrame: true, outgoingSupportsDatagramFrames: true, datagramFitsOutgoingFrame: false, extensionLimitsAllowPayload: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0071")]
    [Requirement("REQ-QUIC-RFC9297-0072")]
    [Requirement("REQ-QUIC-RFC9297-0073")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IntermediaryPolicy_DropsPayloadsThatExceedExtensionLimitsWithoutBuffering()
    {
        Assert.True(Http3DatagramIntermediaryPolicy.IsKnownUnusableDatagramCapsuleLength(capsuleLength: 1024, maximumExtensionPayloadLength: 512));
        Assert.Equal(
            Http3DatagramIntermediaryAction.Drop,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, incomingDatagramFrame: false, outgoingSupportsDatagramFrames: true, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0072")]
    [Requirement("REQ-QUIC-RFC9297-0073")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IntermediaryPolicy_AllowsUsableDatagramCapsuleLengthsWithinExtensionLimits()
    {
        Assert.False(Http3DatagramIntermediaryPolicy.IsKnownUnusableDatagramCapsuleLength(capsuleLength: 512, maximumExtensionPayloadLength: 512));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0075")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void IntermediaryPolicy_NewHttpExtensionsThatUseDatagramsShouldUseCapsuleProtocol(bool usesDatagrams, bool expected)
    {
        Assert.Equal(expected, Http3DatagramIntermediaryPolicy.NewHttpExtensionShouldUseCapsuleProtocol(usesDatagrams));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0075")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IntermediaryPolicy_ExtensionsWithoutHttpDatagramsNeedNotUseCapsuleProtocol()
    {
        Assert.False(Http3DatagramIntermediaryPolicy.NewHttpExtensionShouldUseCapsuleProtocol(usesHttpDatagrams: false));
    }
}
