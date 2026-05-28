// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4P1-0010")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttPacketMayUseRememberedTransportParameterValues()
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.ZeroRtt,
                QuicZeroRttTransportParameterValueSource.Remembered);

        Assert.True(decision.CanUse);
        Assert.Equal(QuicZeroRttTransportParameterUseFailure.None, decision.Failure);
    }

    [Theory]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData((int)QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake, (int)QuicZeroRttTransportParameterUseFailure.UpdatedHandshakeValueInZeroRtt)]
    [InlineData((int)QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame, (int)QuicZeroRttTransportParameterUseFailure.UpdatedOneRttFrameValueInZeroRtt)]
    public void ZeroRttPacketMustNotUseUpdatedTransportParameterValues(
        int source,
        int expectedFailure)
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.ZeroRtt,
                (QuicZeroRttTransportParameterValueSource)source);

        Assert.False(decision.CanUse);
        Assert.Equal((QuicZeroRttTransportParameterUseFailure)expectedFailure, decision.Failure);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, decision.ErrorCode);
    }
}
