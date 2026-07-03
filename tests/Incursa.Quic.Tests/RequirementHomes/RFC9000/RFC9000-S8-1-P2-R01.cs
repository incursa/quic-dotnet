// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-P2-R01")]
public sealed class REQ_QUIC_RFC9000_S8P1_0001
{
    [Theory]
    [InlineData(true, 8, true)]
    [InlineData(true, 7, false)]
    [InlineData(false, 8, false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanConsiderPeerAddressValidated_RequiresEndpointChosenAndAtLeast64BitsOfEntropy(
        bool chosenByEndpoint,
        int connectionIdLength,
        bool expected)
    {
        byte[] connectionId = Enumerable.Range(0, connectionIdLength).Select(index => (byte)index).ToArray();

        Assert.Equal(expected, QuicAddressValidation.CanConsiderPeerAddressValidated(connectionId, chosenByEndpoint));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanConsiderPeerAddressValidated_ReturnsFalseWhenTheEndpointDidNotChooseTheConnectionId()
    {
        byte[] connectionId = Enumerable.Range(0, 8).Select(index => (byte)index).ToArray();

        Assert.False(QuicAddressValidation.CanConsiderPeerAddressValidated(connectionId, chosenByEndpoint: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanConsiderPeerAddressValidated_AllowsExactlySixtyFourBitsOfEntropyWhenChosenByTheEndpoint()
    {
        byte[] connectionId = Enumerable.Range(0, 8).Select(index => (byte)index).ToArray();

        Assert.True(QuicAddressValidation.CanConsiderPeerAddressValidated(connectionId, chosenByEndpoint: true));
    }
}
