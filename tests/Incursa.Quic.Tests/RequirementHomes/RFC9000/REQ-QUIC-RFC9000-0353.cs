// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0353")]
public sealed class REQ_QUIC_RFC9000_0353
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttPacketUsesRememberedTransportParametersOnly()
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.ZeroRtt,
                QuicZeroRttTransportParameterValueSource.Remembered);

        Assert.True(decision.CanUse);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroRttPacketRejectsNonRememberedTransportParameterSource()
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.ZeroRtt,
                QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake);

        Assert.False(decision.CanUse);
        Assert.Equal(QuicZeroRttTransportParameterUseFailure.UpdatedHandshakeValueInZeroRtt, decision.Failure);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ZeroRttPacketRejectsUnknownTransportParameterSource()
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.ZeroRtt,
                QuicZeroRttTransportParameterValueSource.Unknown);

        Assert.False(decision.CanUse);
        Assert.Equal(QuicZeroRttTransportParameterUseFailure.MissingRememberedValue, decision.Failure);
        Assert.Null(decision.ErrorCode);
    }
}
