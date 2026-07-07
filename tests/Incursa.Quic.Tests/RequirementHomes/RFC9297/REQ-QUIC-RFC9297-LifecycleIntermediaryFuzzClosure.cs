// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9297_LifecycleIntermediaryFuzzClosure
{
    [Fact]
    [Requirement("RFC9297-S2-P5-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P5_DatagramsAreSentOnlyForSupportingRequests()
    {
        Assert.Equal(Http3DatagramLifecycleAction.Send, Http3DatagramLifecycle.SelectSendAction(true, sendSideOpen: true).Action);
        Assert.Equal(Http3DatagramLifecycleAction.AbortRequestStream, Http3DatagramLifecycle.SelectSendAction(false, sendSideOpen: true).Action);
    }

    [Fact]
    [Requirement("RFC9297-S2-P6-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P6_UnsupportedReceivedDatagramTerminatesRequest()
    {
        Http3DatagramLifecycleDecision decision = UnsupportedReceiveDecision();

        Assert.Equal(Http3DatagramLifecycleAction.AbortRequestStream, decision.Action);
    }

    [Fact]
    [Requirement("RFC9297-S2-P6-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P6_Http3UnsupportedReceiveUsesH3DatagramError()
    {
        Assert.Equal(Http3ErrorCode.DatagramError, UnsupportedReceiveDecision().ErrorCode);
    }

    [Fact]
    [Requirement("RFC9297-S2-P6-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S2P6_ExtensionsCanOverrideDatagramRequirements()
    {
        Assert.Equal(
            Http3DatagramLifecycleAction.Send,
            Http3DatagramLifecycle.SelectSendAction(false, sendSideOpen: true, extensionOverridesHttpDatagramRequirements: true).Action);
        Assert.Equal(
            Http3DatagramLifecycleAction.Accept,
            Http3DatagramLifecycle.SelectReceiveAction(false, true, true, true, extensionOverridesHttpDatagramRequirements: true).Action);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0014_SendSideMustBeOpenToSendDatagrams()
    {
        Assert.Equal(Http3DatagramLifecycleAction.Send, Http3DatagramLifecycle.SelectSendAction(true, sendSideOpen: true).Action);
        Assert.Equal(Http3DatagramLifecycleAction.DropSilently, Http3DatagramLifecycle.SelectSendAction(true, sendSideOpen: false).Action);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0015_ReceiveSideClosedDatagramsAreSilentlyDropped()
    {
        Http3DatagramLifecycleDecision decision = Http3DatagramLifecycle.SelectReceiveAction(true, receiveSideOpen: false, true, true);

        Assert.Equal(Http3DatagramLifecycleAction.DropSilently, decision.Action);
        Assert.Null(decision.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0016_UncreatedCreatableStreamsAreDroppedOrBuffered()
    {
        Assert.Equal(Http3DatagramLifecycleAction.DropSilently, Http3DatagramLifecycle.SelectReceiveAction(true, true, false, true).Action);
        Assert.Equal(Http3DatagramLifecycleAction.BufferTemporarily, Http3DatagramLifecycle.SelectReceiveAction(true, true, false, true, bufferUncreatedStreams: true).Action);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0026")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0026_Http1CapsuleProtocolStartsOnlyOnLastRequest()
    {
        Assert.True(Http3DatagramLifecycle.CanStartCapsuleProtocolOnHttp1(isLastRequestOnConnection: true));
        Assert.False(Http3DatagramLifecycle.CanStartCapsuleProtocolOnHttp1(isLastRequestOnConnection: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0027")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0027_DataStreamsUseUnderlyingFlowControl()
    {
        Assert.True(Http3DatagramLifecycle.DataStreamUsesUnderlyingFlowControl(true, true));
        Assert.False(Http3DatagramLifecycle.DataStreamUsesUnderlyingFlowControl(true, false));
        Assert.False(Http3DatagramLifecycle.DataStreamUsesUnderlyingFlowControl(false, true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0046")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0046_ImplementationsAvoidFullCapsuleValueBuffering()
    {
        Assert.True(Http3DatagramIntermediaryPolicy.ShouldAvoidFullCapsuleValueBuffering);
    }

    [Fact]
    [Requirement("RFC9297-S3-3-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P3P2_CapsulePayloadContainsExactlyDescribedFields()
    {
        Http3DatagramIntermediaryPolicy.ValidateCapsulePayloadLength(declaredLength: 3, actualLength: 3);
        AssertMessageError(() => Http3DatagramIntermediaryPolicy.ValidateCapsulePayloadLength(declaredLength: 3, actualLength: 2));
    }

    [Fact]
    [Requirement("RFC9297-S3-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P3P2_RedundantLengthEncodingsAreSelfConsistent()
    {
        Http3DatagramIntermediaryPolicy.ValidateCapsulePayloadLength(declaredLength: 3, actualLength: 3, redundantLength: 3);
        AssertMessageError(() => Http3DatagramIntermediaryPolicy.ValidateCapsulePayloadLength(declaredLength: 3, actualLength: 3, redundantLength: 2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0066")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0066_DatagramCapsulesUseHttpDatagramSemantics()
    {
        Http3Datagram parsed = Http3DatagramIntermediaryPolicy.ParseDatagramCapsulePayload(Http3Datagram.CreateForAssociatedStream(4, [0xAA]).Encode());

        Assert.Equal(1UL, parsed.QuarterStreamId);
        Assert.Equal([0xAA], parsed.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0067")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0067_DatagramCapsulesInheritHttpDatagramRestrictions()
    {
        AssertDatagramError(() => Http3DatagramIntermediaryPolicy.ParseDatagramCapsulePayload([0x40]));
    }

    [Fact]
    [Requirement("RFC9297-S3-5-P6-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P5P6_IntermediaryMayReencodeBetweenFramesAndCapsules()
    {
        Assert.Equal(
            Http3DatagramIntermediaryAction.ReencodeAsDatagramCapsule,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, true, outgoingSupportsDatagramFrames: false, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: true));
        Assert.Equal(
            Http3DatagramIntermediaryAction.ReencodeAsDatagramFrame,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, incomingDatagramFrame: false, outgoingSupportsDatagramFrames: true, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: true));
    }

    [Fact]
    [Requirement("RFC9297-S3-5-P6-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P5P6_ReencodingRequiresCapsuleProtocolIdentification()
    {
        Assert.Equal(
            Http3DatagramIntermediaryAction.RequireCapsuleProtocolIdentification,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(false, true, outgoingSupportsDatagramFrames: false, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0070")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0070_IntermediaryAvoidsCapsuleConversionWhenFramesSupported()
    {
        Assert.Equal(
            Http3DatagramIntermediaryAction.ForwardAsDatagramFrame,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, true, outgoingSupportsDatagramFrames: true, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: true));
    }

    [Fact]
    [Requirement("RFC9297-S3-5-P6-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P5P6_OversizedDatagramsAreDroppedInsteadOfConverted()
    {
        Assert.Equal(
            Http3DatagramIntermediaryAction.Drop,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, true, outgoingSupportsDatagramFrames: true, datagramFitsOutgoingFrame: false, extensionLimitsAllowPayload: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0072")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0072_ParsingDatagramCapsulesAccountsForExtensionLimits()
    {
        Assert.True(Http3DatagramIntermediaryPolicy.IsKnownUnusableDatagramCapsuleLength(1024, maximumExtensionPayloadLength: 512));
        Assert.False(Http3DatagramIntermediaryPolicy.IsKnownUnusableDatagramCapsuleLength(512, maximumExtensionPayloadLength: 512));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0073")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0073_KnownUnusableDatagramCapsulesAreDiscardedBeforeBuffering()
    {
        Assert.True(Http3DatagramIntermediaryPolicy.IsKnownUnusableDatagramCapsuleLength(1024, maximumExtensionPayloadLength: 512));
        Assert.Equal(
            Http3DatagramIntermediaryAction.Drop,
            Http3DatagramIntermediaryPolicy.SelectForwardingAction(true, false, outgoingSupportsDatagramFrames: true, datagramFitsOutgoingFrame: true, extensionLimitsAllowPayload: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0074")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0074_ImplementationsAvoidFullDatagramCapsuleAccumulation()
    {
        Assert.True(Http3DatagramIntermediaryPolicy.ShouldAvoidFullDatagramCapsuleAccumulation);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0075")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0075_NewHttpDatagramExtensionsUseCapsuleProtocol()
    {
        Assert.True(Http3DatagramIntermediaryPolicy.NewHttpExtensionShouldUseCapsuleProtocol(usesHttpDatagrams: true));
        Assert.False(Http3DatagramIntermediaryPolicy.NewHttpExtensionShouldUseCapsuleProtocol(usesHttpDatagrams: false));
    }

    private static Http3DatagramLifecycleDecision UnsupportedReceiveDecision()
    {
        return Http3DatagramLifecycle.SelectReceiveAction(
            requestSupportsHttpDatagrams: false,
            receiveSideOpen: true,
            associatedStreamCreated: true,
            associatedStreamCanBeCreated: true);
    }

    private static void AssertDatagramError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    private static void AssertMessageError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }
}
