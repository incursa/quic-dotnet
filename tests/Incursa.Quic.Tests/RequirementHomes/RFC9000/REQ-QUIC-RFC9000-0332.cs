// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0332")]
public sealed class REQ_QUIC_RFC9000_0332
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0332")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsZeroLengthConnectionIdTransportParameter()
    {
        QuicTransportParameters parameters = new()
        {
            InitialSourceConnectionId = [],
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Client,
            QuicTransportParameterRole.Server);

        Assert.NotNull(parsed.InitialSourceConnectionId);
        Assert.Empty(parsed.InitialSourceConnectionId!);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0332")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryValidateConnectionIdBindings_RejectsMissingZeroLengthInitialSourceConnectionId()
    {
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
        };

        Assert.False(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            ReadOnlySpan<byte>.Empty,
            usedRetry: false,
            ReadOnlySpan<byte>.Empty,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId, validationError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0332")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void PeerTransportParameterCommit_AcceptsZeroLengthInitialSourceConnectionIdBinding()
    {
        QuicConnectionRuntime runtime =
            QuicS7P3ConnectionIdBindingTestSupport.CreateClientRuntimeForPeerTransportParameterCommit();
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = [],
        };

        QuicConnectionTransitionResult result =
            QuicS7P3ConnectionIdBindingTestSupport.CommitPeerTransportParametersThroughClientRuntime(
                runtime,
                peerParameters);

        Assert.True(result.StateChanged);
        Assert.Null(runtime.TerminalState);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.Equal(0, runtime.CurrentPeerDestinationConnectionId.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0332")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void PeerTransportParameterCommit_RejectsMissingZeroLengthInitialSourceConnectionIdBinding()
    {
        QuicConnectionRuntime runtime =
            QuicS7P3ConnectionIdBindingTestSupport.CreateClientRuntimeForPeerTransportParameterCommit();
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
        };

        QuicConnectionTransitionResult result =
            QuicS7P3ConnectionIdBindingTestSupport.CommitPeerTransportParametersThroughClientRuntime(
                runtime,
                peerParameters);

        Assert.True(result.StateChanged);
        QuicS7P3ConnectionIdBindingTestSupport.AssertTransportParameterErrorClose(runtime);
    }
}
