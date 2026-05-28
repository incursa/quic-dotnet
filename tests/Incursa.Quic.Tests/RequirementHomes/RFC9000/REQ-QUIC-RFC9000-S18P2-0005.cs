// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0005">This transport parameter MUST NOT be sent by a client.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
public sealed class REQ_QUIC_RFC9000_S18P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_ServerCanSendStatelessResetToken()
    {
        byte[] statelessResetToken = CreateStatelessResetToken();
        QuicTransportParameters parameters = new()
        {
            StatelessResetToken = statelessResetToken,
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(0x02, statelessResetToken);
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatTransportParameters_ClientCannotSendStatelessResetToken()
    {
        QuicTransportParameters parameters = new()
        {
            StatelessResetToken = CreateStatelessResetToken(),
        };

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            stackalloc byte[32],
            out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    private static byte[] CreateStatelessResetToken()
    {
        return Enumerable.Range(0, 16).Select(value => (byte)(0x30 + value)).ToArray();
    }
}
