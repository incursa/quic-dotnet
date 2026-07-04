// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3DatagramLifecyclePolicyTests
{
    [Fact]
    [Requirement("RFC9297-S2-P5-R01")]
    [Requirement("RFC9297-S2-P6-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramLifecycle_AllowsSupportingRequestsAndExtensionOverrides()
    {
        Assert.Equal(
            Http3DatagramLifecycleAction.Send,
            Http3DatagramLifecycle.SelectSendAction(requestSupportsHttpDatagrams: true, sendSideOpen: true).Action);
        Assert.Equal(
            Http3DatagramLifecycleAction.Send,
            Http3DatagramLifecycle.SelectSendAction(requestSupportsHttpDatagrams: false, sendSideOpen: true, extensionOverridesHttpDatagramRequirements: true).Action);
    }

    [Fact]
    [Requirement("RFC9297-S2-P5-R01")]
    [Requirement("RFC9297-S2-P6-R01")]
    [Requirement("RFC9297-S2-P6-S1-R01")]
    [Requirement("RFC9297-S2-P6-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramLifecycle_AbortsUnsupportedRequestsWithH3DatagramError()
    {
        Http3DatagramLifecycleDecision decision = Http3DatagramLifecycle.SelectReceiveAction(
            requestSupportsHttpDatagrams: false,
            receiveSideOpen: true,
            associatedStreamCreated: true,
            associatedStreamCanBeCreated: true);

        Assert.Equal(Http3DatagramLifecycleAction.AbortRequestStream, decision.Action);
        Assert.Equal(Http3ErrorCode.DatagramError, decision.ErrorCode);
    }

    [Fact]
    [Requirement("RFC9297-S2-P6-R01")]
    [Requirement("RFC9297-S2-P6-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramLifecycle_UnsupportedReceiveMapsToRequestAbort()
    {
        Http3DatagramLifecycleDecision decision = Http3DatagramLifecycle.SelectReceiveAction(
            requestSupportsHttpDatagrams: false,
            receiveSideOpen: true,
            associatedStreamCreated: true,
            associatedStreamCanBeCreated: true);

        Assert.Equal(Http3DatagramLifecycleAction.AbortRequestStream, decision.Action);
        Assert.Equal(Http3ErrorCode.DatagramError, decision.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramLifecycle_SendsOnlyWhenSendSideIsOpen()
    {
        Assert.Equal(
            Http3DatagramLifecycleAction.Send,
            Http3DatagramLifecycle.SelectSendAction(requestSupportsHttpDatagrams: true, sendSideOpen: true).Action);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0014")]
    [Requirement("REQ-QUIC-RFC9297-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramLifecycle_SilentlyDropsAfterStreamSideClose()
    {
        Assert.Equal(
            Http3DatagramLifecycleAction.DropSilently,
            Http3DatagramLifecycle.SelectSendAction(requestSupportsHttpDatagrams: true, sendSideOpen: false).Action);
        Assert.Equal(
            Http3DatagramLifecycleAction.DropSilently,
            Http3DatagramLifecycle.SelectReceiveAction(true, receiveSideOpen: false, associatedStreamCreated: true, associatedStreamCanBeCreated: true).Action);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0015")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramLifecycle_ReceiveSideCloseDropsWithoutError()
    {
        Http3DatagramLifecycleDecision decision = Http3DatagramLifecycle.SelectReceiveAction(
            requestSupportsHttpDatagrams: true,
            receiveSideOpen: false,
            associatedStreamCreated: true,
            associatedStreamCanBeCreated: true);

        Assert.Equal(Http3DatagramLifecycleAction.DropSilently, decision.Action);
        Assert.Null(decision.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramLifecycle_BuffersOrDropsDatagramsForUncreatedCreatableStreams()
    {
        Assert.Equal(
            Http3DatagramLifecycleAction.BufferTemporarily,
            Http3DatagramLifecycle.SelectReceiveAction(true, true, associatedStreamCreated: false, associatedStreamCanBeCreated: true, bufferUncreatedStreams: true).Action);
        Assert.Equal(
            Http3DatagramLifecycleAction.DropSilently,
            Http3DatagramLifecycle.SelectReceiveAction(true, true, associatedStreamCreated: false, associatedStreamCanBeCreated: true).Action);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramLifecycle_DoesNotBufferAlreadyCreatedStreams()
    {
        Assert.Equal(
            Http3DatagramLifecycleAction.Accept,
            Http3DatagramLifecycle.SelectReceiveAction(true, true, associatedStreamCreated: true, associatedStreamCanBeCreated: true, bufferUncreatedStreams: true).Action);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0026")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void DatagramLifecycle_Http1CapsuleProtocolStartsOnlyOnLastRequest(bool isLastRequest, bool expected)
    {
        Assert.Equal(expected, Http3DatagramLifecycle.CanStartCapsuleProtocolOnHttp1(isLastRequest));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0026")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramLifecycle_Http1NonLastRequestsCannotStartCapsuleProtocol()
    {
        Assert.False(Http3DatagramLifecycle.CanStartCapsuleProtocolOnHttp1(isLastRequestOnConnection: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0027")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramLifecycle_DataStreamsUseBothUnderlyingFlowControlLayers()
    {
        Assert.True(Http3DatagramLifecycle.DataStreamUsesUnderlyingFlowControl(connectionFlowControlEnabled: true, streamFlowControlEnabled: true));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0027")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void DatagramLifecycle_DataStreamsAreNotCompliantWhenAFlowControlLayerIsMissing(bool connectionFlowControl, bool streamFlowControl)
    {
        Assert.False(Http3DatagramLifecycle.DataStreamUsesUnderlyingFlowControl(connectionFlowControl, streamFlowControl));
    }
}
