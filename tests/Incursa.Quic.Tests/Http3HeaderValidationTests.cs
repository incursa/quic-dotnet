// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3HeaderValidationTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidateRequestHeaders_CommonGet_Passes()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(CommonRequestHeaders());

        Assert.Equal("GET", result.Method);
        Assert.Equal("https", result.Scheme);
        Assert.Equal("example.com", result.Authority);
        Assert.Equal("/", result.Path);
    }

    [Theory]
    [InlineData("/plaintext")]
    [InlineData("/json")]
    public void DecodeAndValidateRequestHeaders_TechEmpowerGet_PreservesFields(string path)
    {
        QPackFieldLine[] expected = TechEmpowerRequestHeaders(path);
        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(QPackEncoder.EncodeFieldSection(expected));

        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false);

        Assert.Equal(expected, decoded);
        Assert.Equal("GET", result.Method);
        Assert.Equal("https", result.Scheme);
        Assert.Equal("localhost:5444", result.Authority);
        Assert.Equal(path, result.Path);
        Assert.Contains(decoded, header => header.Name == "user-agent" && header.Value == "h2load");
        Assert.Contains(decoded, header => header.Name == "accept" && header.Value == "*/*");
    }

    [Theory]
    [InlineData("/plaintext")]
    [InlineData("/json")]
    public void DecodeValidateAndMaterializeRequest_TechEmpowerGet_PreservesRequestSemantics(string path)
    {
        QPackFieldLine[] expected = TechEmpowerRequestHeaders(path);
        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(QPackEncoder.EncodeFieldSection(expected));
        Http3RequestMessageValidator validator = new();

        validator.ReceiveHeaders(decoded);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        Http3Request request = new(
            result.Method ?? string.Empty,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            headers);

        Assert.Equal("GET", request.Method);
        Assert.Equal("https", request.Scheme);
        Assert.Equal("localhost:5444", request.Authority);
        Assert.Equal(path, request.Path);
        Assert.Equal(0, request.Body.Length);
        Assert.Equal(expected, request.Headers);
        Assert.Equal(expected.Select(static header => header.Name), request.Headers.Select(static header => header.Name));
        Assert.Contains(request.Headers, header => header.Name == "user-agent" && header.Value == "h2load");
        Assert.Contains(request.Headers, header => header.Name == "accept" && header.Value == "*/*");
    }

    [Theory]
    [InlineData("/plaintext")]
    [InlineData("/json")]
    public void ServerOwnedDecodeValidateAndMaterializeRequest_TechEmpowerGet_PreservesRequestSemantics(string path)
    {
        QPackFieldLine[] expected = TechEmpowerRequestHeaders(path);
        IReadOnlyList<QPackFieldLine> decoded = DecodeServerOwnedRequestHeaders(expected);
        Http3RequestMessageValidator validator = new();

        validator.ReceiveOwnedHeaders(decoded);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        Http3Request request = new(
            result.Method ?? string.Empty,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            headers);

        Assert.Equal("GET", request.Method);
        Assert.Equal("https", request.Scheme);
        Assert.Equal("localhost:5444", request.Authority);
        Assert.Equal(path, request.Path);
        Assert.Equal(0, request.Body.Length);
        Assert.Equal(expected, request.Headers);
        Assert.Equal(expected.Select(static header => header.Name), request.Headers.Select(static header => header.Name));
        Assert.Contains(request.Headers, header => header.Name == ":method" && header.Value == "GET");
        Assert.Contains(request.Headers, header => header.Name == ":scheme" && header.Value == "https");
        Assert.Contains(request.Headers, header => header.Name == ":authority" && header.Value == "localhost:5444");
        Assert.Contains(request.Headers, header => header.Name == ":path" && header.Value == path);
        Assert.Contains(request.Headers, header => header.Name == "user-agent" && header.Value == "h2load");
        Assert.Contains(request.Headers, header => header.Name == "accept" && header.Value == "*/*");
    }

    [Fact]
    public void ServerOwnedDecodeRequestHeaders_UnknownRegularHeader_RemainsAccepted()
    {
        QPackFieldLine[] expected =
        [
            .. TechEmpowerRequestHeaders("/plaintext"),
            new QPackFieldLine("x-benchmark-fixture", "present"),
        ];
        IReadOnlyList<QPackFieldLine> decoded = DecodeServerOwnedRequestHeaders(expected);

        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false);

        Assert.Equal(expected, decoded);
        Assert.Equal("/plaintext", result.Path);
        Assert.Contains(decoded, header => header.Name == "x-benchmark-fixture" && header.Value == "present");
    }

    [Fact]
    public void ServerOwnedDecodeRequestHeaders_DuplicatePseudoHeader_ThrowsMessageError()
    {
        IReadOnlyList<QPackFieldLine> decoded = DecodeServerOwnedRequestHeaders(
        [
            .. TechEmpowerRequestHeaders("/plaintext"),
            new QPackFieldLine(":path", "/other"),
        ]);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void ServerOwnedDecodeRequestHeaders_MissingRequiredPseudoHeader_ThrowsMessageError()
    {
        IReadOnlyList<QPackFieldLine> decoded = DecodeServerOwnedRequestHeaders(
            Without(TechEmpowerRequestHeaders("/json"), ":scheme"));

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void ServerOwnedDecodeRequestHeaders_PseudoHeaderAfterRegularHeader_ThrowsMessageError()
    {
        IReadOnlyList<QPackFieldLine> decoded = DecodeServerOwnedRequestHeaders(
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine("accept", "*/*"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost:5444"),
            new QPackFieldLine(":path", "/plaintext"),
        ]);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void ServerOwnedDecodeRequestHeaders_MalformedQPackFieldSection_ThrowsDecompressionFailed()
    {
        byte[] invalidStaticIndex = [0x00, 0x00, .. QPackInteger.Encode(99, 6, 0xC0)];
        QPackDecoder decoder = new(0, 0);
        Http3FieldLineBuffer destination = new();

        QPackException exception = Assert.Throws<QPackException>(
            () => decoder.DecodeFieldSection(0, invalidStaticIndex, destination));

        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    public void PublicDecodeFieldSection_ReturnsCallerOwnedArray()
    {
        QPackFieldLine[] expected = TechEmpowerRequestHeaders("/plaintext");
        byte[] encoded = QPackEncoder.EncodeFieldSection(expected);
        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(encoded);

        decoded[3] = new QPackFieldLine(":path", "/mutated");
        QPackFieldLine[] decodedAgain = QPackDecoder.DecodeFieldSection(encoded);

        Assert.Equal(expected, decodedAgain);
        Assert.Contains(decodedAgain, header => header.Name == ":path" && header.Value == "/plaintext");
        Assert.DoesNotContain(decodedAgain, header => header.Name == ":path" && header.Value == "/mutated");
    }

    [Fact]
    public void ServerOwnedDecodeRequestHeaders_DoesNotExposeMutableArrayStorage()
    {
        IReadOnlyList<QPackFieldLine> decoded = DecodeServerOwnedRequestHeaders(TechEmpowerRequestHeaders("/plaintext"));

        Assert.IsNotType<QPackFieldLine[]>(decoded);
        Assert.Equal("/plaintext", decoded.Single(header => header.Name == ":path").Value);
    }

    [Fact]
    public void RequestSequence_PublicReceiveHeadersCopiesMutableInput()
    {
        QPackFieldLine[] headers = CommonRequestHeaders();
        Http3RequestMessageValidator validator = new();

        validator.ReceiveHeaders(headers);
        headers[3] = new QPackFieldLine(":path", "/mutated");

        IReadOnlyList<QPackFieldLine> retained = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Assert.Contains(retained, header => header.Name == ":path" && header.Value == "/");
        Assert.DoesNotContain(retained, header => header.Name == ":path" && header.Value == "/mutated");
    }

    [Fact]
    public void DecodeAndValidateRequestHeaders_UnknownRegularHeader_RemainsAccepted()
    {
        QPackFieldLine[] expected =
        [
            .. TechEmpowerRequestHeaders("/plaintext"),
            new QPackFieldLine("x-benchmark-fixture", "present"),
        ];
        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(QPackEncoder.EncodeFieldSection(expected));

        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false);

        Assert.Equal(expected, decoded);
        Assert.Equal("/plaintext", result.Path);
    }

    [Fact]
    public void DecodeAndValidateRequestHeaders_DuplicatePseudoHeader_ThrowsMessageError()
    {
        QPackFieldLine[] headers =
        [
            .. TechEmpowerRequestHeaders("/plaintext"),
            new QPackFieldLine(":path", "/other"),
        ];

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void DecodeAndValidateRequestHeaders_MissingRequiredPseudoHeader_ThrowsMessageError()
    {
        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(
            QPackEncoder.EncodeFieldSection(Without(TechEmpowerRequestHeaders("/json"), ":scheme")));

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void DecodeAndValidateRequestHeaders_PseudoHeaderAfterRegularHeader_ThrowsMessageError()
    {
        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(
            QPackEncoder.EncodeFieldSection(
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine("accept", "*/*"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "localhost:5444"),
                new QPackFieldLine(":path", "/plaintext"),
            ]));

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateRequestHeaders(decoded, validateContentLength: false));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void DecodeAndValidateRequestHeaders_MalformedQPackFieldSection_ThrowsDecompressionFailed()
    {
        byte[] invalidStaticIndex = [0x00, 0x00, .. QPackInteger.Encode(99, 6, 0xC0)];

        QPackException exception = Assert.Throws<QPackException>(() => QPackDecoder.DecodeFieldSection(invalidStaticIndex));

        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ValidateRequestHeaders_HostWithoutAuthority_PassesForHttpScheme()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":path", "/"),
            new QPackFieldLine("host", "example.com"),
        ]);

        Assert.Equal("example.com", result.Authority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ValidateRequestHeaders_ConnectWithAuthority_Passes()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":authority", "example.com:443"),
        ]);

        Assert.Equal("CONNECT", result.Method);
        Assert.Equal("example.com:443", result.Authority);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [MemberData(nameof(MalformedRequestHeaders))]
    public void ValidateRequestHeaders_MalformedConditions_ThrowMessageError(QPackFieldLine[] headers)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3HeaderValidator.ValidateRequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidateResponseHeaders_CommonFinalResponse_Passes()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateResponseHeaders(CommonResponseHeaders());

        Assert.Equal(200, result.StatusCode);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [MemberData(nameof(MalformedResponseHeaders))]
    public void ValidateResponseHeaders_MalformedConditions_ThrowMessageError(QPackFieldLine[] headers)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3HeaderValidator.ValidateResponseHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidateRequestHeaders_ContentLengthMustMatchDataLength()
    {
        QPackFieldLine[] headers =
        [
            .. CommonRequestHeaders(),
            new QPackFieldLine("content-length", "5"),
        ];

        Http3HeaderValidator.ValidateRequestHeaders(headers, receivedDataLength: 5);
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateRequestHeaders(headers, receivedDataLength: 4));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidateResponseHeaders_ContentLengthMustMatchDataLength()
    {
        QPackFieldLine[] headers =
        [
            .. CommonResponseHeaders(),
            new QPackFieldLine("content-length", "5"),
        ];

        Http3HeaderValidator.ValidateResponseHeaders(headers, receivedDataLength: 5);
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateResponseHeaders(headers, receivedDataLength: 6));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ValidateTrailers_RegularFieldsPassButPseudoHeadersFail()
    {
        Http3HeaderValidator.ValidateTrailers([new QPackFieldLine("etag", "\"abc\"")], Http3MessageType.Response);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateTrailers([new QPackFieldLine(":status", "200")], Http3MessageType.Response));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestSequence_DataBeforeHeaders_IsFrameUnexpected()
    {
        Http3RequestMessageValidator validator = new();

        Http3Exception exception = Assert.Throws<Http3Exception>(() => validator.ReceiveData(1));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestSequence_ContentLengthValidatedAtCompletion()
    {
        Http3RequestMessageValidator validator = new();

        validator.ReceiveHeaders(
        [
            .. CommonRequestHeaders(),
            new QPackFieldLine("content-length", "3"),
        ]);
        validator.ReceiveData(3);
        validator.Complete();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequestSequence_TrailersPassWhenSupported()
    {
        Http3RequestMessageValidator validator = new();

        validator.ReceiveHeaders(CommonRequestHeaders());
        validator.ReceiveData(0);
        validator.ReceiveHeaders([new QPackFieldLine("etag", "\"abc\"")], trailersSupported: true);
        validator.Complete();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ResponseSequence_InformationalThenFinal_Passes()
    {
        Http3ResponseSequenceValidator validator = new();

        Assert.False(validator.ReceiveHeaders([new QPackFieldLine(":status", "103")]));
        Assert.True(validator.ReceiveHeaders(
        [
            .. CommonResponseHeaders(),
            new QPackFieldLine("content-length", "5"),
        ]));
        validator.ReceiveData(5);
        validator.Complete();

        Assert.Equal(200, validator.FinalStatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResponseSequence_OwnedHeaders_AvoidsDefensiveCopy()
    {
        Http3ResponseSequenceValidator publicValidator = new();
        QPackFieldLine[] publicHeaders = CommonResponseHeaders();

        Assert.True(publicValidator.ReceiveHeaders(publicHeaders));

        Assert.NotSame(publicHeaders, publicValidator.FinalResponseHeaders);

        Http3ResponseSequenceValidator ownedValidator = new();
        QPackFieldLine[] ownedHeaders = CommonResponseHeaders();

        Assert.True(ownedValidator.ReceiveOwnedHeaders(ownedHeaders));

        Assert.Same(ownedHeaders, ownedValidator.FinalResponseHeaders);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResponseSequence_DataBeforeFinalResponse_IsFrameUnexpected()
    {
        Http3ResponseSequenceValidator validator = new();

        Http3Exception exception = Assert.Throws<Http3Exception>(() => validator.ReceiveData(1));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResponseSequence_SecondFinalResponseWithoutTrailerSupport_IsFrameUnexpected()
    {
        Http3ResponseSequenceValidator validator = new();

        validator.ReceiveHeaders(CommonResponseHeaders());
        Http3Exception exception = Assert.Throws<Http3Exception>(() => validator.ReceiveHeaders(CommonResponseHeaders()));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ResponseSequence_TrailersPassWhenSupported()
    {
        Http3ResponseSequenceValidator validator = new();

        validator.ReceiveHeaders(CommonResponseHeaders());
        validator.ReceiveData(0);
        validator.ReceiveHeaders([new QPackFieldLine("etag", "\"abc\"")], trailersSupported: true);
        validator.Complete();
    }

    public static IEnumerable<object[]> MalformedRequestHeaders()
    {
        yield return Row(Without(CommonRequestHeaders(), ":method"));
        yield return Row(Without(CommonRequestHeaders(), ":scheme"));
        yield return Row(Without(CommonRequestHeaders(), ":path"));
        yield return Row(Without(CommonRequestHeaders(), ":authority"));
        yield return Row([.. CommonRequestHeaders(), new QPackFieldLine(":method", "POST")]);
        yield return Row([new QPackFieldLine("accept", "*/*"), .. CommonRequestHeaders()]);
        yield return Row([.. CommonRequestHeaders(), new QPackFieldLine(":protocol", "webtransport")]);
        yield return Row([new QPackFieldLine(":method", "GET"), new QPackFieldLine(":scheme", "https"), new QPackFieldLine(":authority", "example.com"), new QPackFieldLine(":path", "")]);
        yield return Row([.. CommonRequestHeaders(), new QPackFieldLine("Host", "example.com")]);
        yield return Row([.. CommonRequestHeaders(), new QPackFieldLine("connection", "keep-alive")]);
        yield return Row([.. CommonRequestHeaders(), new QPackFieldLine("transfer-encoding", "chunked")]);
        yield return Row([.. CommonRequestHeaders(), new QPackFieldLine("te", "gzip")]);
        yield return Row([.. CommonRequestHeaders(), new QPackFieldLine("host", "other.example")]);
        yield return Row([.. CommonRequestHeaders(), new QPackFieldLine("content-length", "5"), new QPackFieldLine("content-length", "6")]);
    }

    public static IEnumerable<object[]> MalformedResponseHeaders()
    {
        yield return Row([]);
        yield return Row([new QPackFieldLine(":status", "20")]);
        yield return Row([new QPackFieldLine(":status", "abc")]);
        yield return Row([new QPackFieldLine(":status", "200"), new QPackFieldLine(":status", "204")]);
        yield return Row([new QPackFieldLine("server", "incursa"), new QPackFieldLine(":status", "200")]);
        yield return Row([new QPackFieldLine(":status", "200"), new QPackFieldLine(":method", "GET")]);
        yield return Row([new QPackFieldLine(":status", "200"), new QPackFieldLine("Content-Type", "text/plain")]);
        yield return Row([new QPackFieldLine(":status", "200"), new QPackFieldLine("connection", "close")]);
        yield return Row([new QPackFieldLine(":status", "200"), new QPackFieldLine("te", "trailers")]);
        yield return Row([new QPackFieldLine(":status", "200"), new QPackFieldLine("content-length", "not-a-number")]);
        yield return Row([new QPackFieldLine(":status", "200"), new QPackFieldLine("content-length", "1"), new QPackFieldLine("content-length", "2")]);
    }

    private static QPackFieldLine[] CommonRequestHeaders()
    {
        return
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "example.com"),
            new QPackFieldLine(":path", "/"),
        ];
    }

    private static QPackFieldLine[] TechEmpowerRequestHeaders(string path)
    {
        return
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost:5444"),
            new QPackFieldLine(":path", path),
            new QPackFieldLine("user-agent", "h2load"),
            new QPackFieldLine("accept", "*/*"),
        ];
    }

    private static QPackFieldLine[] CommonResponseHeaders()
    {
        return [new QPackFieldLine(":status", "200"), new QPackFieldLine("content-type", "text/plain")];
    }

    private static QPackFieldLine[] Without(QPackFieldLine[] headers, string name)
    {
        return [.. headers.Where(header => header.Name != name)];
    }

    private static IReadOnlyList<QPackFieldLine> DecodeServerOwnedRequestHeaders(QPackFieldLine[] headers)
    {
        QPackDecoder decoder = new(0, 0);
        Http3FieldLineBuffer destination = new();
        QPackFieldSectionDecodeStatus result = decoder.DecodeFieldSection(0, QPackEncoder.EncodeFieldSection(headers), destination);
        if (result.IsBlocked)
        {
            throw new InvalidOperationException("The server-owned test field section unexpectedly blocked.");
        }

        return destination.CommitToReadOnlyList();
    }

    private static object[] Row(QPackFieldLine[] headers)
    {
        return [headers];
    }
}
