// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0348")]
public sealed class REQ_QUIC_RFC9000_0348
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NonZeroBidirectionalAllowancePermitsClientApplicationDataForZeroRtt()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 1,
            InitialMaxStreamDataBidiRemote = 1,
            InitialMaxStreamsBidi = 1,
        };

        Assert.True(QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(parameters));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroConnectionDataAllowanceDoesNotPermitClientApplicationDataForZeroRtt()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 0,
            InitialMaxStreamDataBidiRemote = 1,
            InitialMaxStreamsBidi = 1,
        };

        Assert.False(QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(parameters));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void OnlyServerInitiatedBidirectionalCreditDoesNotPermitClientApplicationDataForZeroRtt()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 1,
            InitialMaxStreamDataBidiLocal = 1,
            InitialMaxStreamsBidi = 1,
        };

        Assert.False(QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(parameters));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientZeroRttApplicationDataAllowanceRequiresConnectionAndClientStreamCredit()
    {
        for (ulong connectionData = 0; connectionData <= 3; connectionData++)
        {
            for (ulong clientBidirectionalData = 0; clientBidirectionalData <= 3; clientBidirectionalData++)
            {
                for (ulong bidirectionalStreams = 0; bidirectionalStreams <= 2; bidirectionalStreams++)
                {
                    for (ulong clientUnidirectionalData = 0; clientUnidirectionalData <= 3; clientUnidirectionalData++)
                    {
                        for (ulong unidirectionalStreams = 0; unidirectionalStreams <= 2; unidirectionalStreams++)
                        {
                            QuicTransportParameters parameters = new()
                            {
                                InitialMaxData = connectionData,
                                InitialMaxStreamDataBidiRemote = clientBidirectionalData,
                                InitialMaxStreamsBidi = bidirectionalStreams,
                                InitialMaxStreamDataBidiLocal = 3,
                                InitialMaxStreamDataUni = clientUnidirectionalData,
                                InitialMaxStreamsUni = unidirectionalStreams,
                            };

                            bool expected =
                                connectionData > 0 &&
                                ((clientBidirectionalData > 0 && bidirectionalStreams > 0) ||
                                 (clientUnidirectionalData > 0 && unidirectionalStreams > 0));

                            Assert.Equal(
                                expected,
                                QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(parameters));
                        }
                    }
                }
            }
        }
    }
}
