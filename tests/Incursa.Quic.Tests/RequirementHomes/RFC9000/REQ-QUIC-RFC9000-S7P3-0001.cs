// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
public sealed class REQ_QUIC_RFC9000_S7P3_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_AuthenticatesHandshakeConnectionIdChoices()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.ServerInitialSourceConnectionId,
            RetrySourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.RetrySourceConnectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);

        Assert.Equal(parameters.OriginalDestinationConnectionId, parsed.OriginalDestinationConnectionId);
        Assert.Equal(parameters.InitialSourceConnectionId, parsed.InitialSourceConnectionId);
        Assert.Equal(parameters.RetrySourceConnectionId, parsed.RetrySourceConnectionId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryFormatTransportParameters_RoundTripsHandshakeConnectionIdBindings()
    {
        ConnectionIdBindingCase[] scenarios =
        [
            new(
                OriginalDestinationConnectionId: [0x10],
                InitialSourceConnectionId: [0x20],
                RetrySourceConnectionId: [0x30]),
            new(
                OriginalDestinationConnectionId: [0x10, 0x11, 0x12, 0x13],
                InitialSourceConnectionId: [0x20, 0x21],
                RetrySourceConnectionId: [0x30, 0x31, 0x32]),
            new(
                OriginalDestinationConnectionId: [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87],
                InitialSourceConnectionId: [0x90, 0x91, 0x92, 0x93, 0x94, 0x95],
                RetrySourceConnectionId: [0xA0, 0xA1, 0xA2, 0xA3]),
            new(
                OriginalDestinationConnectionId: [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB],
                InitialSourceConnectionId: [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7],
                RetrySourceConnectionId: [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5]),
        ];

        foreach (ConnectionIdBindingCase scenario in scenarios)
        {
            QuicTransportParameters parameters = new()
            {
                OriginalDestinationConnectionId = scenario.OriginalDestinationConnectionId,
                InitialSourceConnectionId = scenario.InitialSourceConnectionId,
                RetrySourceConnectionId = scenario.RetrySourceConnectionId,
            };

            QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
                parameters,
                QuicTransportParameterRole.Server,
                QuicTransportParameterRole.Client);

            Assert.Equal(scenario.OriginalDestinationConnectionId, parsed.OriginalDestinationConnectionId);
            Assert.Equal(scenario.InitialSourceConnectionId, parsed.InitialSourceConnectionId);
            Assert.Equal(scenario.RetrySourceConnectionId, parsed.RetrySourceConnectionId);
        }
    }

    private readonly record struct ConnectionIdBindingCase(
        byte[] OriginalDestinationConnectionId,
        byte[] InitialSourceConnectionId,
        byte[] RetrySourceConnectionId);
}
