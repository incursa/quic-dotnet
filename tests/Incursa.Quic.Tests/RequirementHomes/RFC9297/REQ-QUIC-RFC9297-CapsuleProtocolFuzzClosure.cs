// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9297_CapsuleProtocolFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0036")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0036_CapsuleProtocolRequires101Or2xxStatus()
    {
        Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 101, [], []);
        Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [], []);
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 300, [], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0037")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0037_CapsuleProtocolMessagesCarryNoHttpContent()
    {
        Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [], []);
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [], [], requestContentLength: 1));
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [], [], responseContentLength: 1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0038")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0038_Http2AndHttp3CapsuleProtocolUsesConnect()
    {
        Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [], []);
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("GET", 200, [], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0039")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0039_CapsuleProtocolRejectsContentLength()
    {
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [new QPackFieldLine("content-length", "1")], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0040")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0040_CapsuleProtocolRejectsContentType()
    {
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [new QPackFieldLine("content-type", "application/octet-stream")], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0041")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0041_CapsuleProtocolRejectsTransferEncoding()
    {
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 200, [new QPackFieldLine("transfer-encoding", "chunked")], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0042")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0042_CapsuleProtocolRejectsNoContentStatus()
    {
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 204, [], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0043")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0043_CapsuleProtocolRejectsResetContentStatus()
    {
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 205, [], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0044")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0044_CapsuleProtocolRejectsPartialContentStatus()
    {
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("CONNECT", 206, [], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0045")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0045_CapsuleProtocolViolationsAreMalformedMessages()
    {
        AssertMessageError(() => Http3CapsuleProtocol.ValidateHttp3Usage("GET", 204, [new QPackFieldLine("content-length", "1")], []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0052")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0052_CapsuleProtocolHeaderIsStructuredFieldItem()
    {
        Assert.True(Http3CapsuleProtocol.TryParseCapsuleProtocolHeaderValue("?1; unknown=value", out bool enabled));
        Assert.True(enabled);
        Assert.False(Http3CapsuleProtocol.TryParseCapsuleProtocolHeaderValue("true", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0053")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0053_CapsuleProtocolHeaderValueIsBoolean()
    {
        Assert.True(Http3CapsuleProtocol.TryParseCapsuleProtocolHeaderValue("?1", out bool enabled));
        Assert.True(enabled);
        Assert.True(Http3CapsuleProtocol.TryParseCapsuleProtocolHeaderValue("?0", out enabled));
        Assert.False(enabled);
    }

    [Fact]
    [Requirement("RFC9297-S3-4-P1-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P4P1_NonBooleanCapsuleProtocolValuesAreAbsent()
    {
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([new QPackFieldLine("capsule-protocol", "\"true\"")]));
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([new QPackFieldLine("capsule-protocol", "1")]));
    }

    [Fact]
    [Requirement("RFC9297-S3-4-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P4P1_UnknownParametersAreIgnored()
    {
        Assert.True(Http3CapsuleProtocol.IsCapsuleProtocolInUse([new QPackFieldLine("capsule-protocol", "?1; unknown=value")]));
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([new QPackFieldLine("capsule-protocol", "?0; unknown=value")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0056")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0056_EndpointIndicatesCapsuleProtocolWithTrueHeader()
    {
        Assert.True(Http3CapsuleProtocol.IsCapsuleProtocolInUse([Http3CapsuleProtocol.CreateCapsuleProtocolHeader(enabled: true)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0057")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0057_FalseCapsuleProtocolHeaderIsEquivalentToAbsent()
    {
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([Http3CapsuleProtocol.CreateCapsuleProtocolHeader(enabled: false)]));
        Assert.False(Http3CapsuleProtocol.IsCapsuleProtocolInUse([]));
    }

    [Fact]
    [Requirement("RFC9297-S3-4-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P4P3_IntermediaryCanUseHeaderForUnknownUpgradeToken()
    {
        Assert.True(Http3CapsuleProtocol.CanProcessUnknownUpgradeToken([Http3CapsuleProtocol.CreateCapsuleProtocolHeader()]));
    }

    [Fact]
    [Requirement("RFC9297-S3-4-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P4P4_HeaderNotUsedOutside101Or2xxResponses()
    {
        Assert.True(Http3CapsuleProtocol.IsAllowedCapsuleProtocolStatus(101));
        Assert.True(Http3CapsuleProtocol.IsAllowedCapsuleProtocolStatus(200));
        Assert.False(Http3CapsuleProtocol.IsAllowedCapsuleProtocolStatus(300));
    }

    [Fact]
    [Requirement("RFC9297-S3-4-P5-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S3P4P5_EndpointsShouldSendCapsuleProtocolHeader()
    {
        Assert.True(Http3CapsuleProtocol.ShouldSendCapsuleProtocolHeader(usingCapsuleProtocol: true));
        Assert.False(Http3CapsuleProtocol.ShouldSendCapsuleProtocolHeader(usingCapsuleProtocol: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0079")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0079_RegistryFieldNameIsCapsuleProtocol()
    {
        Assert.Equal("capsule-protocol", Http3CapsuleProtocol.CapsuleProtocolHeaderName);
    }

    [Fact]
    [Requirement("RFC9297-S5-4-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P4P1_CapsuleTypeRegistrationRequiresLabel()
    {
        Http3CapsuleProtocol.ValidateCapsuleTypeRegistration(Http3CapsuleProtocol.DatagramCapsuleTypeLabel, Http3Capsule.DatagramCapsuleType);
        Assert.Throws<ArgumentException>(() => Http3CapsuleProtocol.ValidateCapsuleTypeRegistration("", Http3Capsule.DatagramCapsuleType));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9297-0081")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0081_ReservedCapsuleTypeValuesFollowFormula()
    {
        Assert.True(Http3CapsuleProtocol.IsReservedCapsuleType(0x17));
        Assert.True(Http3CapsuleProtocol.IsReservedCapsuleType(0x40));
        Assert.False(Http3CapsuleProtocol.IsReservedCapsuleType(0x18));
    }

    [Fact]
    [Requirement("RFC9297-S5-4-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P4P3_ReservedCapsuleTypeValuesAreNotAssignedByIana()
    {
        Assert.False(Http3CapsuleProtocol.CanIanaAssignCapsuleType(0x17));
        Assert.False(Http3CapsuleProtocol.CanIanaAssignCapsuleType(0x40));
    }

    [Fact]
    [Requirement("RFC9297-S5-4-P3-S2-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P4P3_ReservedCapsuleTypeValuesDoNotAppearAssigned()
    {
        Assert.True(Http3CapsuleProtocol.IsReservedCapsuleType(0x17));
        Assert.False(Http3CapsuleProtocol.CanIanaAssignCapsuleType(0x17));
    }

    private static void AssertMessageError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }
}
