// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S21P1P1P1-0001")]
public sealed class REQ_QUIC_RFC9000_S21P1P1P1_0001
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
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CanConsiderPeerAddressValidatedFuzz_AcceptsOnlyEndpointChosenConnectionIdsWithAtLeast64BitsOfEntropy()
    {
        foreach (bool chosenByEndpoint in new[] { false, true })
        {
            for (int connectionIdLength = 0; connectionIdLength <= 20; connectionIdLength++)
            {
                byte[] connectionId = Enumerable
                    .Range(0, connectionIdLength)
                    .Select(index => (byte)(0xA0 + index))
                    .ToArray();
                bool expected = chosenByEndpoint && connectionIdLength >= 8;

                Assert.Equal(expected, QuicAddressValidation.CanConsiderPeerAddressValidated(connectionId, chosenByEndpoint));
            }
        }
    }
}
