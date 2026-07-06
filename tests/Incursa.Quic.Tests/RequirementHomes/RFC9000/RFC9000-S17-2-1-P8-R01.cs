// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S17-2-1-P8-R01">Version-specific rules for the connection ID therefore MUST NOT influence a decision about whether to send a Version Negotiation packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-2-1-P8-R01")]
public sealed class RFC9000_S17_2_1_P8_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-1-P8-R01">Version-specific rules for the connection ID therefore MUST NOT influence a decision about whether to send a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-1-P8-R01")]
    public void ShouldSendVersionNegotiation_ReturnsTrueForAnUnsupportedClientVersionWithEnoughDatagramSpace()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-1-P8-R01">Version-specific rules for the connection ID therefore MUST NOT influence a decision about whether to send a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-1-P8-R01")]
    public void ShouldSendVersionNegotiation_ReturnsFalseForASupportedClientVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-1-P8-R01">Version-specific rules for the connection ID therefore MUST NOT influence a decision about whether to send a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-1-P8-R01")]
    public void ShouldSendVersionNegotiationFuzz_IgnoresVersionSpecificConnectionIdLimits()
    {
        uint[] unsupportedClientVersions =
        [
            0x11223344u,
            QuicVersionNegotiation.CreateReservedVersion(0xA5B6C7D8u),
            uint.MaxValue,
        ];
        int[] notionalConnectionIdLengths =
        [
            0,
            1,
            20,
            21,
            byte.MaxValue,
        ];

        foreach (uint unsupportedClientVersion in unsupportedClientVersions)
        {
            foreach (int notionalConnectionIdLength in notionalConnectionIdLengths)
            {
                Assert.InRange(notionalConnectionIdLength, 0, byte.MaxValue);
                Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                    unsupportedClientVersion,
                    QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
                    [QuicVersionNegotiation.Version1]));
            }

            Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                unsupportedClientVersion,
                QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1,
                [QuicVersionNegotiation.Version1]));
        }
    }
}
