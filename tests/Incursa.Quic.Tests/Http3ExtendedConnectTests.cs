// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ExtendedConnectTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0002")]
    [Requirement("REQ-QUIC-RFC9220-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SettingsIdentifier_UsesRegisteredEnableConnectProtocolValue()
    {
        Assert.Equal(0x08L, (long)Http3SettingIdentifier.EnableConnectProtocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SettingsModel_DefaultsEnableConnectProtocolToZero()
    {
        Http3Settings settings = new();

        Assert.Equal(0UL, settings.EnableConnectProtocol);
        Assert.DoesNotContain(
            Assert.IsType<Http3SettingsFrame>(ReadFrame(Http3SettingsWriter.WriteSettingsFrame(settings))).Settings,
            setting => setting.Identifier == (ulong)Http3SettingIdentifier.EnableConnectProtocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0002")]
    [Requirement("REQ-QUIC-RFC9220-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SettingsWriter_And_Parser_RoundTripEnableConnectProtocol()
    {
        Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(
            ReadFrame(Http3SettingsWriter.WriteSettingsFrame(new Http3Settings(enableConnectProtocol: 1))));

        Assert.Equal(1UL, frame.Values.EnableConnectProtocol);
        Assert.Contains(
            frame.Settings,
            setting => setting.Identifier == (ulong)Http3SettingIdentifier.EnableConnectProtocol && setting.Value == 1);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0002")]
    [Requirement("REQ-QUIC-RFC9220-0007")]
    [Requirement("REQ-QUIC-RFC9220-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SettingsParser_RejectsDuplicateEnableConnectProtocol()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, [0x08, 0x01, 0x08, 0x00]);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadFrame(encoded));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HeaderValidator_ExtendedConnectWebSocket_PreservesRfc8441PseudoHeaders()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "example.com"),
            new QPackFieldLine(":path", "/chat"),
        ]);

        Assert.Equal("CONNECT", result.Method);
        Assert.Equal(Http3ExtendedConnect.WebSocketProtocol, result.Protocol);
        Assert.Equal("https", result.Scheme);
        Assert.Equal("example.com", result.Authority);
        Assert.Equal("/chat", result.Path);
        Assert.True(Http3ExtendedConnect.IsExtendedConnect(result));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9220-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [MemberData(nameof(MalformedExtendedConnectHeaders))]
    public void HeaderValidator_MalformedExtendedConnect_ThrowsMessageError(QPackFieldLine[] headers)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3HeaderValidator.ValidateRequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnsupportedProtocolResponse_UsesRecommendedNotImplementedStatus()
    {
        Http3ServerResponse response = Http3ExtendedConnect.CreateUnsupportedProtocolResponse("webtransport");

        Assert.Equal(501, response.StatusCode);
        Assert.Contains(response.Headers, header => header.Name == "content-type" && header.Value == "text/plain");
        Assert.False(Http3ExtendedConnect.IsSupportedProtocol("webtransport"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SupportedWebSocketProtocol_DoesNotRequireUnsupportedResponse()
    {
        Assert.True(Http3ExtendedConnect.IsSupportedProtocol(Http3ExtendedConnect.WebSocketProtocol));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnsupportedProtocolResponse_CanIncludeProblemDetails()
    {
        Http3ServerResponse response = Http3ExtendedConnect.CreateUnsupportedProtocolResponse("webtransport", includeProblemDetails: true);

        Assert.Equal(501, response.StatusCode);
        Assert.Contains(response.Headers, header => header.Name == "content-type" && header.Value == "application/problem+json");
        Assert.Contains("\"protocol\":\"webtransport\"", System.Text.Encoding.UTF8.GetString(response.Body.Span), StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosureMapping_OrderlyClosure_UsesFin()
    {
        Http3ExtendedConnectClosure closure = Http3ExtendedConnect.MapOrderlyClosure();

        Assert.True(closure.FinishStream);
        Assert.Null(closure.ResetErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClosureMapping_OrderlyClosure_DoesNotUseReset()
    {
        Assert.Null(Http3ExtendedConnect.MapOrderlyClosure().ResetErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosureMapping_ResetException_UsesRequestCancelled()
    {
        Http3ExtendedConnectClosure closure = Http3ExtendedConnect.MapResetException();

        Assert.False(closure.FinishStream);
        Assert.Equal(Http3ErrorCode.RequestCancelled, closure.ResetErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClosureMapping_ResetException_DoesNotUseFin()
    {
        Assert.False(Http3ExtendedConnect.MapResetException().FinishStream);
    }

    public static IEnumerable<object[]> MalformedExtendedConnectHeaders()
    {
        yield return Row(
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "example.com"),
            new QPackFieldLine(":path", "/chat"),
        ]);
        yield return Row(
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
            new QPackFieldLine(":authority", "example.com"),
            new QPackFieldLine(":path", "/chat"),
        ]);
        yield return Row(
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":path", "/chat"),
        ]);
        yield return Row(
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "example.com"),
        ]);
    }

    private static Http3Frame ReadFrame(byte[] encoded)
    {
        return Assert.Single(new Http3FrameReader().Read(encoded));
    }

    private static object[] Row(QPackFieldLine[] headers)
    {
        return [headers];
    }
}
