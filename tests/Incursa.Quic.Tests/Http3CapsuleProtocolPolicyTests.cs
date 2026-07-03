// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3CapsuleProtocolPolicyTests
{
    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0036")]
    [Requirement("REQ-QUIC-RFC9297-0042")]
    [Requirement("REQ-QUIC-RFC9297-0043")]
    [Requirement("REQ-QUIC-RFC9297-0044")]
    [Requirement("RFC9297-S3-4-P4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(101)]
    [InlineData(200)]
    [InlineData(299)]
    public void CapsuleProtocol_AllowsSwitchingProtocolsAndSuccessfulStatuses(int statusCode)
    {
        Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", statusCode, [], []);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0036")]
    [Requirement("REQ-QUIC-RFC9297-0042")]
    [Requirement("REQ-QUIC-RFC9297-0043")]
    [Requirement("REQ-QUIC-RFC9297-0044")]
    [Requirement("REQ-QUIC-RFC9297-0045")]
    [Requirement("RFC9297-S3-4-P4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(100)]
    [InlineData(204)]
    [InlineData(205)]
    [InlineData(206)]
    [InlineData(300)]
    public void CapsuleProtocol_RejectsDisallowedStatusesAsMalformed(int statusCode)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", statusCode, [], []));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleProtocol_AllowsHttp3ConnectRequests()
    {
        Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [], []);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0038")]
    [Requirement("REQ-QUIC-RFC9297-0045")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapsuleProtocol_RejectsNonConnectHttp3RequestsAsMalformed()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3CapsuleProtocol.ValidateHttp3Usage("GET", 200, [], []));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0037")]
    [Requirement("REQ-QUIC-RFC9297-0039")]
    [Requirement("REQ-QUIC-RFC9297-0040")]
    [Requirement("REQ-QUIC-RFC9297-0041")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleProtocol_AllowsMessagesWithoutContentHeadersOrBodyBytes()
    {
        Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [], []);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0037")]
    [Requirement("REQ-QUIC-RFC9297-0039")]
    [Requirement("REQ-QUIC-RFC9297-0040")]
    [Requirement("REQ-QUIC-RFC9297-0041")]
    [Requirement("REQ-QUIC-RFC9297-0045")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("content-length")]
    [InlineData("content-type")]
    [InlineData("transfer-encoding")]
    public void CapsuleProtocol_RejectsContentHeadersAsMalformed(string headerName)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [new QPackFieldLine(headerName, "1")], []));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0037")]
    [Requirement("REQ-QUIC-RFC9297-0045")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapsuleProtocol_RejectsContentBytesAsMalformed()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [], [], requestContentLength: 1));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0045")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleProtocol_ViolationsMapToMalformedMessageError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3CapsuleProtocol.ValidateHttp3Usage("GET", 204, [new QPackFieldLine("content-length", "1")], []));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0052")]
    [Requirement("REQ-QUIC-RFC9297-0053")]
    [Requirement("REQ-QUIC-RFC9297-0055")]
    [Requirement("REQ-QUIC-RFC9297-0056")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleProtocolHeader_ParsesTrueBooleanAndIgnoresUnknownParameters()
    {
        Assert.True(Http3CapsuleProtocol.TryParseCapsuleProtocolHeaderValue("?1; unknown=value", out bool enabled));
        Assert.True(enabled);
        Assert.True(Http3CapsuleProtocol.IsCapsuleProtocolInUse([new QPackFieldLine("capsule-protocol", "?1; unknown=value")]));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0052")]
    [Requirement("REQ-QUIC-RFC9297-0053")]
    [Requirement("RFC9297-S3-4-P1-S1-R02")]
    [Requirement("REQ-QUIC-RFC9297-0057")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("?0")]
    [InlineData("\"true\"")]
    [InlineData("1")]
    public void CapsuleProtocolHeader_TreatsFalseOrNonBooleanValuesAsAbsent(string value)
    {
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([new QPackFieldLine("capsule-protocol", value)]));
    }

    [Theory]
    [Requirement("RFC9297-S3-4-P1-S1-R02")]
    [Requirement("REQ-QUIC-RFC9297-0057")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("?0")]
    [InlineData("\"true\"")]
    public void CapsuleProtocolHeader_AbsenceEquivalentValuesDoNotEnableCapsules(string value)
    {
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([new QPackFieldLine("capsule-protocol", value)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0055")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapsuleProtocolHeader_UnknownParametersDoNotOverrideFalseBooleanValues()
    {
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([new QPackFieldLine("capsule-protocol", "?0; unknown=value")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0056")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapsuleProtocolHeader_AbsentOrFalseHeaderDoesNotSignalCapsuleProtocolUse()
    {
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([]));
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([Http3CapsuleProtocol.CreateCapsuleProtocolHeader(enabled: false)]));
    }

    [Fact]
    [Requirement("RFC9297-S3-4-P3-R01")]
    [Requirement("RFC9297-S3-4-P5-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleProtocolHeader_AllowsIntermediaryProcessingAndRecommendedEmission()
    {
        QPackFieldLine header = Http3CapsuleProtocol.CreateCapsuleProtocolHeader();

        Assert.True(Http3CapsuleProtocol.CanProcessUnknownUpgradeToken([header]));
        Assert.True(Http3CapsuleProtocol.ShouldSendCapsuleProtocolHeader(usingCapsuleProtocol: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0079")]
    [Requirement("RFC9297-S5-4-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapsuleProtocolRegistry_ExposesRegisteredFieldNameAndRequiresTypeLabel()
    {
        Assert.Equal("capsule-protocol", Http3CapsuleProtocol.CapsuleProtocolHeaderName);
        Http3CapsuleProtocol.ValidateCapsuleTypeRegistration(Http3CapsuleProtocol.DatagramCapsuleTypeLabel, Http3Capsule.DatagramCapsuleType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0079")]
    [Requirement("RFC9297-S5-4-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapsuleProtocolRegistry_RejectsMissingTypeLabels()
    {
        Assert.Throws<ArgumentException>(() => Http3CapsuleProtocol.ValidateCapsuleTypeRegistration("", Http3Capsule.DatagramCapsuleType));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0081")]
    [Requirement("REQ-QUIC-RFC9297-0082")]
    [Requirement("REQ-QUIC-RFC9297-0083")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(0x17UL)]
    [InlineData(0x40UL)]
    public void CapsuleProtocolRegistry_IdentifiesReservedCapsuleTypeValues(ulong value)
    {
        Assert.True(Http3CapsuleProtocol.IsReservedCapsuleType(value));
        Assert.False(Http3CapsuleProtocol.CanIanaAssignCapsuleType(value));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9297-0081")]
    [Requirement("REQ-QUIC-RFC9297-0082")]
    [Requirement("REQ-QUIC-RFC9297-0083")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(0x00UL)]
    [InlineData(0x18UL)]
    public void CapsuleProtocolRegistry_AllowsNonReservedCapsuleTypeValues(ulong value)
    {
        Assert.False(Http3CapsuleProtocol.IsReservedCapsuleType(value));
        Assert.True(Http3CapsuleProtocol.CanIanaAssignCapsuleType(value));
    }
}
