namespace Incursa.Quic.Tests;

public sealed class Http3HeaderValidationTests
{
    [Fact]
    public void ValidateRequestHeaders_CommonGet_Passes()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(CommonRequestHeaders());

        Assert.Equal("GET", result.Method);
        Assert.Equal("https", result.Scheme);
        Assert.Equal("example.com", result.Authority);
        Assert.Equal("/", result.Path);
    }

    [Fact]
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
    [MemberData(nameof(MalformedRequestHeaders))]
    public void ValidateRequestHeaders_MalformedConditions_ThrowMessageError(QPackFieldLine[] headers)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3HeaderValidator.ValidateRequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void ValidateResponseHeaders_CommonFinalResponse_Passes()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateResponseHeaders(CommonResponseHeaders());

        Assert.Equal(200, result.StatusCode);
    }

    [Theory]
    [MemberData(nameof(MalformedResponseHeaders))]
    public void ValidateResponseHeaders_MalformedConditions_ThrowMessageError(QPackFieldLine[] headers)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3HeaderValidator.ValidateResponseHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
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
    public void ValidateTrailers_RegularFieldsPassButPseudoHeadersFail()
    {
        Http3HeaderValidator.ValidateTrailers([new QPackFieldLine("etag", "\"abc\"")], Http3MessageType.Response);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateTrailers([new QPackFieldLine(":status", "200")], Http3MessageType.Response));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void RequestSequence_DataBeforeHeaders_IsFrameUnexpected()
    {
        Http3RequestMessageValidator validator = new();

        Http3Exception exception = Assert.Throws<Http3Exception>(() => validator.ReceiveData(1));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
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
    public void RequestSequence_TrailersPassWhenSupported()
    {
        Http3RequestMessageValidator validator = new();

        validator.ReceiveHeaders(CommonRequestHeaders());
        validator.ReceiveData(0);
        validator.ReceiveHeaders([new QPackFieldLine("etag", "\"abc\"")], trailersSupported: true);
        validator.Complete();
    }

    [Fact]
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
    public void ResponseSequence_DataBeforeFinalResponse_IsFrameUnexpected()
    {
        Http3ResponseSequenceValidator validator = new();

        Http3Exception exception = Assert.Throws<Http3Exception>(() => validator.ReceiveData(1));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    public void ResponseSequence_SecondFinalResponseWithoutTrailerSupport_IsFrameUnexpected()
    {
        Http3ResponseSequenceValidator validator = new();

        validator.ReceiveHeaders(CommonResponseHeaders());
        Http3Exception exception = Assert.Throws<Http3Exception>(() => validator.ReceiveHeaders(CommonResponseHeaders()));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
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

    private static QPackFieldLine[] CommonResponseHeaders()
    {
        return [new QPackFieldLine(":status", "200"), new QPackFieldLine("content-type", "text/plain")];
    }

    private static QPackFieldLine[] Without(QPackFieldLine[] headers, string name)
    {
        return [.. headers.Where(header => header.Name != name)];
    }

    private static object[] Row(QPackFieldLine[] headers)
    {
        return [headers];
    }
}
