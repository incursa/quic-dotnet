// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4P1-0012")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0012
{
    [Theory]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData((int)QuicTlsEncryptionLevel.ZeroRtt)]
    [InlineData((int)QuicTlsEncryptionLevel.Initial)]
    [InlineData((int)QuicTlsEncryptionLevel.Handshake)]
    public void UpdatedTransportParameterValuesDoNotApplyOutsideOneRttPackets(int packetProtectionLevel)
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                (QuicTlsEncryptionLevel)packetProtectionLevel,
                QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake);

        Assert.False(decision.CanUse);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, decision.ErrorCode);
    }

    [Theory]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [InlineData((int)QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake)]
    [InlineData((int)QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame)]
    public void UpdatedTransportParameterValuesApplyToOneRttPackets(int source)
    {
        QuicZeroRttTransportParameterUseDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                QuicTlsEncryptionLevel.OneRtt,
                (QuicZeroRttTransportParameterValueSource)source);

        Assert.True(decision.CanUse);
        Assert.Equal(QuicZeroRttTransportParameterUseFailure.None, decision.Failure);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S7P4P1-0012")]
    public void Fuzz_UpdatedTransportParameterValuesOnlyApplyToOneRttPackets()
    {
        QuicZeroRttTransportParameterValueSource[] updatedSources =
        [
            QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake,
            QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame,
        ];

        foreach (QuicTlsEncryptionLevel packetProtectionLevel in Enum.GetValues<QuicTlsEncryptionLevel>())
        {
            foreach (QuicZeroRttTransportParameterValueSource updatedSource in updatedSources)
            {
                QuicZeroRttTransportParameterUseDecision decision =
                    QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                        packetProtectionLevel,
                        updatedSource);

                if (packetProtectionLevel == QuicTlsEncryptionLevel.OneRtt)
                {
                    Assert.True(decision.CanUse);
                    Assert.Equal(QuicZeroRttTransportParameterUseFailure.None, decision.Failure);
                    Assert.Null(decision.ErrorCode);
                    continue;
                }

                Assert.False(decision.CanUse);
                Assert.Equal(QuicTransportErrorCode.ProtocolViolation, decision.ErrorCode);

                QuicZeroRttTransportParameterUseFailure expectedFailure =
                    packetProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt
                        ? updatedSource switch
                        {
                            QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake
                                => QuicZeroRttTransportParameterUseFailure.UpdatedHandshakeValueInZeroRtt,
                            QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame
                                => QuicZeroRttTransportParameterUseFailure.UpdatedOneRttFrameValueInZeroRtt,
                            _ => throw new InvalidOperationException("Unexpected updated source."),
                        }
                        : QuicZeroRttTransportParameterUseFailure.UpdatedValueOutsideOneRtt;

                Assert.Equal(expectedFailure, decision.Failure);
            }
        }
    }
}
