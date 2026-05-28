// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0334">An endpoint MUST treat receipt of a transport parameter with an invalid value as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0334")]
public sealed class REQ_QUIC_RFC9000_0334
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0334")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsAnInvalidActiveConnectionIdLimitValue()
    {
        byte[] invalidActiveConnectionIdLimit = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0E,
                QuicVarintTestData.EncodeMinimal(1)));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            invalidActiveConnectionIdLimit,
            QuicTransportParameterRole.Client,
            out _));
    }
}
