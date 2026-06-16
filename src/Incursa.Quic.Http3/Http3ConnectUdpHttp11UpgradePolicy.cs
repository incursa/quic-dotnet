// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9298 HTTP/1.1 CONNECT-UDP upgrade policy helpers.
/// </summary>
public static class Http3ConnectUdpHttp11UpgradePolicy
{
    /// <summary>
    /// Gets the required HTTP/1.1 request method.
    /// </summary>
    public const string RequestMethod = "GET";

    /// <summary>
    /// Gets the successful HTTP/1.1 upgrade response status code.
    /// </summary>
    public const int SwitchingProtocolsStatusCode = 101;

    /// <summary>
    /// Gets the recommended malformed request response status code.
    /// </summary>
    public const int MalformedRequestStatusCode = 400;

    /// <summary>
    /// Indicates that servers must send the relevant HTTP setting for CONNECT-UDP support.
    /// </summary>
    public const bool ServerMustSendHttpSetting = true;

    /// <summary>
    /// Builds the required HTTP/1.1 CONNECT-UDP upgrade request header fields.
    /// </summary>
    public static IReadOnlyList<QPackFieldLine> BuildUpgradeRequestHeaders(string proxyAuthority)
    {
        ArgumentException.ThrowIfNullOrEmpty(proxyAuthority);
        return
        [
            new QPackFieldLine("host", proxyAuthority),
            new QPackFieldLine("connection", "Upgrade"),
            new QPackFieldLine("upgrade", Http3ConnectUdp.ProtocolToken),
            Http3CapsuleProtocol.CreateCapsuleProtocolHeader(),
        ];
    }

    /// <summary>
    /// Builds the required HTTP/1.1 CONNECT-UDP upgrade response header fields.
    /// </summary>
    public static IReadOnlyList<QPackFieldLine> BuildSwitchingProtocolsResponseHeaders()
    {
        return
        [
            new QPackFieldLine("connection", "Upgrade"),
            new QPackFieldLine("upgrade", Http3ConnectUdp.ProtocolToken),
        ];
    }

    /// <summary>
    /// Validates an HTTP/1.1 CONNECT-UDP upgrade request.
    /// </summary>
    public static void ValidateUpgradeRequest(string method, IReadOnlyList<QPackFieldLine> headers, ulong contentLength = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentNullException.ThrowIfNull(headers);

        if (!string.Equals(method, RequestMethod, StringComparison.Ordinal))
        {
            throw Malformed("CONNECT-UDP over HTTP/1.1 requires GET.");
        }

        if (CountHeaders(headers, "host") != 1)
        {
            throw Malformed("CONNECT-UDP over HTTP/1.1 requires a single Host header field.");
        }

        if (!ContainsToken(headers, "connection", "upgrade"))
        {
            throw Malformed("CONNECT-UDP over HTTP/1.1 requires Connection: Upgrade.");
        }

        if (CountHeaderValue(headers, "upgrade", Http3ConnectUdp.ProtocolToken) != 1)
        {
            throw Malformed("CONNECT-UDP over HTTP/1.1 requires a single Upgrade: connect-udp field.");
        }

        ValidateNoContent(headers, contentLength);
    }

    /// <summary>
    /// Validates a successful HTTP/1.1 CONNECT-UDP upgrade response.
    /// </summary>
    public static void ValidateSwitchingProtocolsResponse(int statusCode, IReadOnlyList<QPackFieldLine> headers, ulong contentLength = 0)
    {
        ArgumentNullException.ThrowIfNull(headers);

        if (statusCode != SwitchingProtocolsStatusCode)
        {
            throw Malformed("CONNECT-UDP over HTTP/1.1 requires 101 Switching Protocols.");
        }

        if (!ContainsToken(headers, "connection", "upgrade"))
        {
            throw Malformed("CONNECT-UDP over HTTP/1.1 responses require Connection: Upgrade.");
        }

        if (CountHeaderValue(headers, "upgrade", Http3ConnectUdp.ProtocolToken) != 1)
        {
            throw Malformed("CONNECT-UDP over HTTP/1.1 responses require a single Upgrade: connect-udp field.");
        }

        ValidateNoContent(headers, contentLength);
    }

    /// <summary>
    /// Returns true when HTTP/1.1 upgrade response validation succeeds.
    /// </summary>
    public static bool CanProceedAfterUpgradeResponse(int statusCode, IReadOnlyList<QPackFieldLine> headers, ulong contentLength = 0)
    {
        try
        {
            ValidateSwitchingProtocolsResponse(statusCode, headers, contentLength);
            return true;
        }
        catch (Http3Exception)
        {
            return false;
        }
    }

    private static int CountHeaders(IReadOnlyList<QPackFieldLine> headers, string name)
    {
        int count = 0;
        for (int index = 0; index < headers.Count; index++)
        {
            if (StringComparer.OrdinalIgnoreCase.Equals(headers[index].Name, name))
            {
                count++;
            }
        }

        return count;
    }

    private static int CountHeaderValue(IReadOnlyList<QPackFieldLine> headers, string name, string value)
    {
        int count = 0;
        for (int index = 0; index < headers.Count; index++)
        {
            QPackFieldLine header = headers[index];
            if (StringComparer.OrdinalIgnoreCase.Equals(header.Name, name)
                && StringComparer.OrdinalIgnoreCase.Equals(header.Value, value))
            {
                count++;
            }
        }

        return count;
    }

    private static bool ContainsToken(IReadOnlyList<QPackFieldLine> headers, string name, string token)
    {
        for (int index = 0; index < headers.Count; index++)
        {
            QPackFieldLine header = headers[index];
            if (!StringComparer.OrdinalIgnoreCase.Equals(header.Name, name))
            {
                continue;
            }

            string[] values = header.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            for (int valueIndex = 0; valueIndex < values.Length; valueIndex++)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(values[valueIndex], token))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static void ValidateNoContent(IReadOnlyList<QPackFieldLine> headers, ulong contentLength)
    {
        if (contentLength != 0)
        {
            throw Malformed("CONNECT-UDP HTTP/1.1 upgrade messages must not carry content.");
        }

        if (CountHeaders(headers, "content-length") != 0 || CountHeaders(headers, "content-type") != 0)
        {
            throw Malformed("CONNECT-UDP HTTP/1.1 upgrade messages must not include content header fields.");
        }
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
