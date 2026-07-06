// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P3-0008">In either role, an application protocol MAY control resource allocation for receive buffers by setting flow control limits both for streams and for the connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P3-0008")]
public sealed class REQ_QUIC_RFC9000_S5P3_0008
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P3-0008">In either role, an application protocol MAY control resource allocation for receive buffers by setting flow control limits both for streams and for the connection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P3-0008")]
    public void TryFormatTransportParameters_AllowsConfiguringFlowControlLimitsForEitherRole(bool senderIsClient)
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 1024,
            InitialMaxStreamDataBidiRemote = 2048,
            InitialMaxStreamDataUni = 512,
        };

        QuicTransportParameterRole senderRole = senderIsClient
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;
        QuicTransportParameterRole receiverRole = senderIsClient
            ? QuicTransportParameterRole.Server
            : QuicTransportParameterRole.Client;

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x04, QuicVarintTestData.EncodeMinimal(4096)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x05, QuicVarintTestData.EncodeMinimal(1024)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x06, QuicVarintTestData.EncodeMinimal(2048)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x07, QuicVarintTestData.EncodeMinimal(512)));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            receiverRole,
            out QuicTransportParameters parsed));

        Assert.Equal(4096UL, parsed.InitialMaxData);
        Assert.Equal(1024UL, parsed.InitialMaxStreamDataBidiLocal);
        Assert.Equal(2048UL, parsed.InitialMaxStreamDataBidiRemote);
        Assert.Equal(512UL, parsed.InitialMaxStreamDataUni);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S5P3-0008")]
    public void Fuzz_TryFormatTransportParameters_RoundTripsFlowControlLimitsForEitherRole()
    {
        FlowControlLimitCase[] scenarios =
        [
            new(SenderIsClient: true, InitialMaxData: 1, BidiLocal: 1, BidiRemote: 1, Uni: 1),
            new(SenderIsClient: false, InitialMaxData: 63, BidiLocal: 62, BidiRemote: 61, Uni: 60),
            new(SenderIsClient: true, InitialMaxData: 64, BidiLocal: 128, BidiRemote: 256, Uni: 512),
            new(SenderIsClient: false, InitialMaxData: 16_383, BidiLocal: 4_096, BidiRemote: 8_192, Uni: 16_383),
            new(SenderIsClient: true, InitialMaxData: 16_384, BidiLocal: 32_768, BidiRemote: 65_536, Uni: 131_072),
        ];

        foreach (FlowControlLimitCase scenario in scenarios)
        {
            QuicTransportParameters parameters = new()
            {
                InitialMaxData = scenario.InitialMaxData,
                InitialMaxStreamDataBidiLocal = scenario.BidiLocal,
                InitialMaxStreamDataBidiRemote = scenario.BidiRemote,
                InitialMaxStreamDataUni = scenario.Uni,
            };

            QuicTransportParameterRole senderRole = scenario.SenderIsClient
                ? QuicTransportParameterRole.Client
                : QuicTransportParameterRole.Server;
            QuicTransportParameterRole receiverRole = scenario.SenderIsClient
                ? QuicTransportParameterRole.Server
                : QuicTransportParameterRole.Client;

            byte[] destination = new byte[256];
            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                senderRole,
                destination,
                out int bytesWritten));

            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                destination.AsSpan(0, bytesWritten),
                receiverRole,
                out QuicTransportParameters parsed));

            Assert.Equal(scenario.InitialMaxData, parsed.InitialMaxData);
            Assert.Equal(scenario.BidiLocal, parsed.InitialMaxStreamDataBidiLocal);
            Assert.Equal(scenario.BidiRemote, parsed.InitialMaxStreamDataBidiRemote);
            Assert.Equal(scenario.Uni, parsed.InitialMaxStreamDataUni);
        }
    }

    private readonly record struct FlowControlLimitCase(
        bool SenderIsClient,
        ulong InitialMaxData,
        ulong BidiLocal,
        ulong BidiRemote,
        ulong Uni);
}
