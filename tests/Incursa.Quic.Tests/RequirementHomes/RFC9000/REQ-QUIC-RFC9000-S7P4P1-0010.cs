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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S7P4P1-0010")]
    public void Fuzz_ZeroRttPacketsOnlyUseRememberedTransportParameterValues()
    {
        ZeroRttValueSourceCase[] cases =
        [
            new(
                QuicZeroRttTransportParameterValueSource.Unknown,
                false,
                QuicZeroRttTransportParameterUseFailure.MissingRememberedValue,
                null),
            new(
                QuicZeroRttTransportParameterValueSource.Remembered,
                true,
                QuicZeroRttTransportParameterUseFailure.None,
                null),
            new(
                QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake,
                false,
                QuicZeroRttTransportParameterUseFailure.UpdatedHandshakeValueInZeroRtt,
                QuicTransportErrorCode.ProtocolViolation),
            new(
                QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame,
                false,
                QuicZeroRttTransportParameterUseFailure.UpdatedOneRttFrameValueInZeroRtt,
                QuicTransportErrorCode.ProtocolViolation),
        ];

        foreach (ZeroRttValueSourceCase candidate in cases)
        {
            QuicZeroRttTransportParameterUseDecision decision =
                QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                    QuicTlsEncryptionLevel.ZeroRtt,
                    candidate.ValueSource);

            Assert.Equal(candidate.CanUse, decision.CanUse);
            Assert.Equal(candidate.ExpectedFailure, decision.Failure);
            Assert.Equal(candidate.ExpectedError, decision.ErrorCode);
        }
    }

    private readonly record struct ZeroRttValueSourceCase(
        QuicZeroRttTransportParameterValueSource ValueSource,
        bool CanUse,
        QuicZeroRttTransportParameterUseFailure ExpectedFailure,
        QuicTransportErrorCode? ExpectedError);
}
