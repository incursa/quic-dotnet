// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S3-0009")]
[Requirement("REQ-QUIC-RFC9221-S3-0010")]
public sealed class REQ_QUIC_RFC9221_S3_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CreateRememberedTransportParametersForClientZeroRtt_RemembersMaxDatagramFrameSize()
    {
        QuicTransportParameters remembered = Assert.IsType<QuicTransportParameters>(
            QuicZeroRttTransportParameterPolicy.CreateRememberedTransportParametersForClientZeroRtt(
                new QuicTransportParameters
                {
                    MaxDatagramFrameSize = 1200,
                }));

        Assert.Equal(1200UL, remembered.MaxDatagramFrameSize);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EvaluateServerZeroRttAcceptance_RejectsReducedRememberedMaxDatagramFrameSize()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                new QuicTransportParameters
                {
                    ActiveConnectionIdLimit = 2,
                    InitialMaxData = 1,
                    InitialMaxStreamDataBidiLocal = 1,
                    InitialMaxStreamDataBidiRemote = 1,
                    InitialMaxStreamDataUni = 1,
                    InitialMaxStreamsBidi = 1,
                    InitialMaxStreamsUni = 1,
                    MaxDatagramFrameSize = 1200,
                },
                new QuicTransportParameters
                {
                    ActiveConnectionIdLimit = 2,
                    InitialMaxData = 1,
                    InitialMaxStreamDataBidiLocal = 1,
                    InitialMaxStreamDataBidiRemote = 1,
                    InitialMaxStreamDataUni = 1,
                    InitialMaxStreamsBidi = 1,
                    InitialMaxStreamsUni = 1,
                    MaxDatagramFrameSize = 1199,
                });

        Assert.False(decision.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedOptionalValue, decision.Failure);
        Assert.Equal("max_datagram_frame_size", decision.ParameterName);
    }
}
