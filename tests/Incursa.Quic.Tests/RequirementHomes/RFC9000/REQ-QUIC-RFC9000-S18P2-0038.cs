// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0038")]
public sealed class REQ_QUIC_RFC9000_S18P2_0038
{
    [Theory]
    [MemberData(nameof(ServerOnlyServerParseCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseTransportParameters_ServerRejectsEachServerOnlyTransportParameterFromPeer(byte[] encoded)
    {
        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseTransportParameters_ServerAcceptsClientAllowedTransportParameters()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, [0x11, 0x22]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));
        Assert.Equal(25UL, parsed.MaxIdleTimeout);
        Assert.Equal([0x11, 0x22], parsed.InitialSourceConnectionId);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0001">This transport parameter MUST only be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0004">This transport parameter MAY be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0005">This transport parameter MUST NOT be sent by a client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0038">A server MUST treat receipt of any of these transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0038")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseTransportParameters_RejectsServerOnlyParametersWhenReceivingAsServer()
    {
        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x02, Enumerable.Range(0, 16).Select(value => (byte)(0x50 + value)).ToArray());

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            tuple,
            QuicTransportParameterRole.Server,
            out _));
    }

    public static IEnumerable<object[]> ServerOnlyServerParseCases()
    {
        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x00, [0x01, 0x02]),
        };

        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x02,
                Enumerable.Range(0, 16).Select(value => (byte)(0x50 + value)).ToArray()),
        };

        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, CreatePreferredAddressValue()),
        };

        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x10, [0x33, 0x44]),
        };
    }

    private static byte[] CreatePreferredAddressValue()
    {
        return QuicTransportParameterTestData.BuildPreferredAddressValue(
            [192, 0, 2, 1],
            443,
            [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
            8443,
            [0xAA],
            Enumerable.Range(0, 16).Select(value => (byte)(0x40 + value)).ToArray());
    }
}
