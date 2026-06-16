// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 HTTP/3 CONNECT-IP request and response policy helpers.
/// </summary>
public static class Http3ConnectIp
{
    private const int MinimumSuccessfulStatusCode = 200;
    private const int MaximumSuccessfulStatusCode = 299;

    /// <summary>
    /// Indicates that CONNECT-IP servers must advertise Extended CONNECT support with the HTTP setting for HTTP/2 and HTTP/3.
    /// </summary>
    public const bool ServerMustSendExtendedConnectSetting = true;

    /// <summary>
    /// Builds HTTP/3 CONNECT-IP request headers for a URI Template expansion.
    /// </summary>
    public static IReadOnlyList<QPackFieldLine> BuildHttp3RequestHeaders(
        Http3ConnectIpUriTemplate template,
        string? target = null,
        string? ipproto = null,
        IReadOnlyDictionary<string, string>? additionalVariables = null)
    {
        ArgumentNullException.ThrowIfNull(template);

        Http3ConnectIpRequestTarget requestTarget = template.Expand(target, ipproto, additionalVariables);
        return
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ConnectIpFoundationPolicy.ProtocolToken),
            new QPackFieldLine(":scheme", requestTarget.Scheme),
            new QPackFieldLine(":authority", requestTarget.Authority),
            new QPackFieldLine(":path", requestTarget.PathAndQuery),
            Http3CapsuleProtocol.CreateCapsuleProtocolHeader(),
        ];
    }

    /// <summary>
    /// Validates HTTP/3 CONNECT-IP request headers before tunnel setup.
    /// </summary>
    public static Http3HeaderValidationResult ValidateHttp3RequestHeaders(IReadOnlyList<QPackFieldLine> headers, ulong contentLength = 0)
    {
        ArgumentNullException.ThrowIfNull(headers);

        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, contentLength);
        if (result.Method != "CONNECT")
        {
            throw Malformed("CONNECT-IP over HTTP/3 requires :method CONNECT.");
        }

        if (!string.Equals(result.Protocol, Http3ConnectIpFoundationPolicy.ProtocolToken, StringComparison.Ordinal))
        {
            throw Malformed("CONNECT-IP over HTTP/3 requires :protocol connect-ip.");
        }

        if (!Http3CapsuleProtocol.IsCapsuleProtocolInUse(headers))
        {
            throw Malformed("CONNECT-IP over HTTP/3 requires the Capsule Protocol.");
        }

        Http3CapsuleProtocol.ValidateHttp3Usage(result.Method, responseStatusCode: 200, headers, responseHeaders: [], requestContentLength: contentLength);
        return result;
    }

    /// <summary>
    /// Validates HTTP/3 CONNECT-IP request headers against a specific URI Template expansion.
    /// </summary>
    public static Http3HeaderValidationResult ValidateHttp3RequestHeaders(
        IReadOnlyList<QPackFieldLine> headers,
        Http3ConnectIpUriTemplate template,
        string? target = null,
        string? ipproto = null,
        IReadOnlyDictionary<string, string>? additionalVariables = null,
        ulong contentLength = 0)
    {
        ArgumentNullException.ThrowIfNull(template);

        Http3HeaderValidationResult result = ValidateHttp3RequestHeaders(headers, contentLength);
        Http3ConnectIpRequestTarget expected = template.Expand(target, ipproto, additionalVariables);
        if (!string.Equals(result.Authority, expected.Authority, StringComparison.Ordinal)
            || !string.Equals(result.Scheme, expected.Scheme, StringComparison.Ordinal)
            || !string.Equals(result.Path, expected.PathAndQuery, StringComparison.Ordinal))
        {
            throw Malformed("CONNECT-IP over HTTP/3 request pseudo-headers must match the URI Template expansion.");
        }

        return result;
    }

    /// <summary>
    /// Validates a successful HTTP/3 CONNECT-IP response.
    /// </summary>
    public static void ValidateSuccessfulHttp3Response(
        int statusCode,
        IReadOnlyList<QPackFieldLine> requestHeaders,
        IReadOnlyList<QPackFieldLine> responseHeaders,
        ulong requestContentLength = 0,
        ulong responseContentLength = 0)
    {
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentNullException.ThrowIfNull(responseHeaders);

        Http3HeaderValidationResult request = ValidateHttp3RequestHeaders(requestHeaders, requestContentLength);
        if (statusCode is < MinimumSuccessfulStatusCode or > MaximumSuccessfulStatusCode)
        {
            throw Malformed("CONNECT-IP over HTTP/3 requires a 2xx response before proxying succeeds.");
        }

        Http3CapsuleProtocol.ValidateHttp3Usage(
            request.Method ?? "CONNECT",
            statusCode,
            requestHeaders,
            responseHeaders,
            requestContentLength,
            responseContentLength);
    }

    /// <summary>
    /// Returns true when response validation succeeds and proxying can proceed.
    /// </summary>
    public static bool CanProceedAfterHttp3Response(
        int statusCode,
        IReadOnlyList<QPackFieldLine> requestHeaders,
        IReadOnlyList<QPackFieldLine> responseHeaders,
        ulong requestContentLength = 0,
        ulong responseContentLength = 0)
    {
        try
        {
            ValidateSuccessfulHttp3Response(statusCode, requestHeaders, responseHeaders, requestContentLength, responseContentLength);
            return true;
        }
        catch (Http3Exception)
        {
            return false;
        }
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
