// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-4-P7-R01")]
public sealed class REQ_QUIC_RFC9000_0335
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="RFC9000-S7-4-P6-R01">An endpoint MUST treat receipt of a transport parameter with an invalid value as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S7-4-P7-R01">An endpoint MUST NOT send a parameter more than once in a given transport parameters extension.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S7-4-P7-S1-R01">An endpoint SHOULD treat receipt of duplicate transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S7-4-P6-R01")]
    [Requirement("RFC9000-S7-4-P7-R01")]
    [Requirement("RFC9000-S7-4-P7-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_UsesEachParameterOnceAndParsesBack()
    {
        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 25,
            DisableActiveMigration = true,
            ActiveConnectionIdLimit = 2,
        };

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0C, []),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0E, QuicVarintTestData.EncodeMinimal(2)));

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.Equal(25UL, parsed.MaxIdleTimeout);
        Assert.True(parsed.DisableActiveMigration);
        Assert.Equal(2UL, parsed.ActiveConnectionIdLimit);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S7-4-P7-R01">An endpoint MUST NOT send a parameter more than once in a given transport parameters extension.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S7-4-P7-S1-R01">An endpoint SHOULD treat receipt of duplicate transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S7-4-P7-R01")]
    [Requirement("RFC9000-S7-4-P7-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsDuplicateTransportParameters()
    {
        byte[] duplicateKnownParameter = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(33)));

        byte[] duplicateUnknownParameter = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xAA]),
            QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xBB]));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            duplicateKnownParameter,
            QuicTransportParameterRole.Client,
            out _));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            duplicateUnknownParameter,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Theory]
    [InlineData(0x01UL, 25UL, 33UL)]
    [InlineData(0x03UL, 1024UL, 2048UL)]
    [InlineData(0x0EUL, 2UL, 8UL)]
    [InlineData(27UL, 170UL, 187UL)]
    [Requirement("RFC9000-S7-4-P7-R01")]
    [Requirement("RFC9000-S7-4-P7-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryParseTransportParametersRejectsDuplicateParameterIds(
        ulong parameterId,
        ulong firstValue,
        ulong secondValue)
    {
        byte[] duplicateParameterBlock = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(parameterId, QuicVarintTestData.EncodeMinimal(firstValue)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(parameterId, QuicVarintTestData.EncodeMinimal(secondValue)));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            duplicateParameterBlock,
            QuicTransportParameterRole.Client,
            out _));
    }
}
