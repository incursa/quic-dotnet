// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9220 Extended CONNECT constants and mapping helpers.
/// </summary>
public static class Http3ExtendedConnect
{
    /// <summary>
    /// The RFC 9220 WebSocket Extended CONNECT protocol token.
    /// </summary>
    public const string WebSocketProtocol = "websocket";

    /// <summary>
    /// The recommended status code for unsupported Extended CONNECT protocol values.
    /// </summary>
    public const int UnsupportedProtocolStatusCode = 501;

    /// <summary>
    /// Determines whether a validated request is an Extended CONNECT request.
    /// </summary>
    public static bool IsExtendedConnect(Http3HeaderValidationResult request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Method == "CONNECT" && request.Protocol is not null;
    }

    /// <summary>
    /// Determines whether the protocol token is supported by the built-in HTTP/3 Extended CONNECT floor.
    /// </summary>
    public static bool IsSupportedProtocol(string? protocol)
    {
        return string.Equals(protocol, WebSocketProtocol, StringComparison.Ordinal);
    }

    /// <summary>
    /// Creates the recommended unsupported-protocol response for Extended CONNECT.
    /// </summary>
    public static Http3ServerResponse CreateUnsupportedProtocolResponse(string? protocol, bool includeProblemDetails = false)
    {
        if (!includeProblemDetails)
        {
            return new Http3ServerResponse(
                UnsupportedProtocolStatusCode,
                "Not Implemented"u8.ToArray(),
                [new QPackFieldLine("content-type", "text/plain")]);
        }

        byte[] body = Encoding.UTF8.GetBytes(
            string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $$"""{"type":"about:blank","title":"Unsupported Extended CONNECT protocol","status":{{UnsupportedProtocolStatusCode}},"protocol":"{{EscapeJsonString(protocol)}}"}"""));

        return new Http3ServerResponse(
            UnsupportedProtocolStatusCode,
            body,
            [new QPackFieldLine("content-type", "application/problem+json")]);
    }

    /// <summary>
    /// Maps an orderly TCP-level closure to stream FIN.
    /// </summary>
    public static Http3ExtendedConnectClosure MapOrderlyClosure()
    {
        return new Http3ExtendedConnectClosure(finishStream: true, resetErrorCode: null);
    }

    /// <summary>
    /// Maps a TCP-level RST exception to H3_REQUEST_CANCELLED.
    /// </summary>
    public static Http3ExtendedConnectClosure MapResetException()
    {
        return new Http3ExtendedConnectClosure(finishStream: false, Http3ErrorCode.RequestCancelled);
    }

    private static string EscapeJsonString(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
    }
}
