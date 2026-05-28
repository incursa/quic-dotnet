// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0323">Each endpoint MUST include the value of the Source Connection ID field from the first Initial packet it sent in the initial_source_connection_id transport parameter.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0323")]
public sealed class REQ_QUIC_RFC9000_0323
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0323")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsInitialSourceConnectionId()
    {
        QuicTransportParameters parameters = new()
        {
            InitialSourceConnectionId = [0x11, 0x22],
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.True(parameters.InitialSourceConnectionId!.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId!));
        Assert.Null(parsed.ActiveConnectionIdLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0323")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryValidateConnectionIdBindings_RejectsMissingInitialSourceConnectionId()
    {
        Assert.False(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Server,
            ReadOnlySpan<byte>.Empty,
            QuicS7P3ConnectionIdBindingTestSupport.ClientInitialSourceConnectionId,
            usedRetry: false,
            ReadOnlySpan<byte>.Empty,
            new QuicTransportParameters(),
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId, validationError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0323")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatTransportParameters_EmitsZeroLengthInitialSourceConnectionId()
    {
        QuicTransportParameters parameters = new()
        {
            InitialSourceConnectionId = [],
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Client,
            QuicTransportParameterRole.Server);

        Assert.NotNull(parsed.InitialSourceConnectionId);
        Assert.Empty(parsed.InitialSourceConnectionId!);
    }
}
