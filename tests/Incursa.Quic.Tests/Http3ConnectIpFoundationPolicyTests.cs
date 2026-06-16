// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpFoundationPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Foundation_DoesNotConveyIpHeaderFields()
    {
        Http3ConnectIpFoundationPolicy.ValidatePayloadMechanismScope(
            conveysIpHeaderFields: false,
            tunnelsOtherIpProtocols: false);

        Assert.False(Http3ConnectIpFoundationPolicy.ConveysIpHeaderFields);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Foundation_RejectsIpHeaderFieldConveyance()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpFoundationPolicy.ValidatePayloadMechanismScope(
            conveysIpHeaderFields: true,
            tunnelsOtherIpProtocols: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Foundation_DoesNotTunnelOtherIpProtocols()
    {
        Http3ConnectIpFoundationPolicy.ValidatePayloadMechanismScope(
            conveysIpHeaderFields: false,
            tunnelsOtherIpProtocols: false);

        Assert.False(Http3ConnectIpFoundationPolicy.TunnelsOtherIpProtocols);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Foundation_RejectsOtherProtocolTunneling()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpFoundationPolicy.ValidatePayloadMechanismScope(
            conveysIpHeaderFields: false,
            tunnelsOtherIpProtocols: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Foundation_EncodesAndDecodesQuicVariableLengthIntegers()
    {
        byte[] encoded = Http3ConnectIpFoundationPolicy.EncodeVariableLengthInteger(15293);

        Assert.True(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger(encoded, out ulong value, out int bytesConsumed));
        Assert.Equal(15293UL, value);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Foundation_RejectsTruncatedVariableLengthIntegers()
    {
        Assert.False(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger([0x40], out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Foundation_AcceptsNonMinimalVariableLengthIntegerEncodings()
    {
        byte[] nonMinimalOne = [0x40, 0x01];

        Assert.True(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger(nonMinimalOne, out ulong value, out int bytesConsumed));
        Assert.Equal(1UL, value);
        Assert.Equal(2, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Foundation_DoesNotRequireNonMinimalVariableLengthIntegerEncodings()
    {
        byte[] minimalOne = Http3ConnectIpFoundationPolicy.EncodeVariableLengthInteger(1);

        Assert.Equal([0x01], minimalOne);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Foundation_UsesEntireConnectionScopeWhenHttpVersionDoesNotMultiplexStreams()
    {
        Assert.Equal(
            Http3ConnectIpStreamReferenceScope.EntireConnection,
            Http3ConnectIpFoundationPolicy.GetStreamReferenceScope(httpVersionSupportsMultiplexingStreams: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Foundation_UsesRequestStreamScopeWhenHttpVersionMultiplexesStreams()
    {
        Assert.Equal(
            Http3ConnectIpStreamReferenceScope.RequestStream,
            Http3ConnectIpFoundationPolicy.GetStreamReferenceScope(httpVersionSupportsMultiplexingStreams: true));
    }
}
