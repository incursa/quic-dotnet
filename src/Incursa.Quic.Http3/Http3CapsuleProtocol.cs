// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9297 Capsule Protocol policy and registry helpers.
/// </summary>
public static class Http3CapsuleProtocol
{
    private const int MinimumSuccessfulStatusCode = 200;
    private const int MaximumSuccessfulStatusCode = 299;
    private const int SwitchingProtocolsStatusCode = 101;
    private const int NoContentStatusCode = 204;
    private const int ResetContentStatusCode = 205;
    private const int PartialContentStatusCode = 206;
    private const ulong ReservedCapsuleTypeOffset = 0x17;
    private const ulong ReservedCapsuleTypeMultiplier = 0x29;

    /// <summary>
    /// Gets the registered HTTP field name used to signal Capsule Protocol use.
    /// </summary>
    public const string CapsuleProtocolHeaderName = "capsule-protocol";

    /// <summary>
    /// Gets the registered DATAGRAM Capsule Type label.
    /// </summary>
    public const string DatagramCapsuleTypeLabel = "DATAGRAM";

    /// <summary>
    /// Creates a Capsule-Protocol header field.
    /// </summary>
    public static QPackFieldLine CreateCapsuleProtocolHeader(bool enabled = true)
    {
        return new QPackFieldLine(CapsuleProtocolHeaderName, enabled ? "?1" : "?0");
    }

    /// <summary>
    /// Returns true when the field section contains a true Capsule-Protocol value.
    /// </summary>
    public static bool IsCapsuleProtocolInUse(IReadOnlyList<QPackFieldLine> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        for (int index = 0; index < headers.Count; index++)
        {
            QPackFieldLine header = headers[index];
            if (StringComparer.OrdinalIgnoreCase.Equals(header.Name, CapsuleProtocolHeaderName)
                && TryParseCapsuleProtocolHeaderValue(header.Value, out bool enabled)
                && enabled)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Parses the Capsule-Protocol field value as an Item Structured Field Boolean.
    /// </summary>
    public static bool TryParseCapsuleProtocolHeaderValue(string value, out bool enabled)
    {
        enabled = false;
        ArgumentNullException.ThrowIfNull(value);

        ReadOnlySpan<char> span = value.AsSpan().Trim();
        if (span.Length < 2 || span[0] != '?')
        {
            return false;
        }

        enabled = span[1] switch
        {
            '1' => true,
            '0' => false,
            _ => false,
        };

        if (span[1] is not ('0' or '1'))
        {
            return false;
        }

        ReadOnlySpan<char> remainder = span[2..].TrimStart();
        return remainder.IsEmpty || remainder[0] == ';';
    }

    /// <summary>
    /// Validates Capsule Protocol preconditions for an HTTP/3 request and response.
    /// </summary>
    public static void ValidateHttp3Usage(
        string method,
        int responseStatusCode,
        IReadOnlyList<QPackFieldLine> requestHeaders,
        IReadOnlyList<QPackFieldLine> responseHeaders,
        ulong requestContentLength = 0,
        ulong responseContentLength = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentNullException.ThrowIfNull(responseHeaders);

        if (method != "CONNECT")
        {
            throw Malformed("Capsule Protocol over HTTP/3 is restricted to CONNECT requests.");
        }

        if (!IsAllowedCapsuleProtocolStatus(responseStatusCode))
        {
            throw Malformed("Capsule Protocol requires a 2xx or 101 response status and excludes 204, 205, and 206.");
        }

        ValidateNoContent(requestHeaders, requestContentLength);
        ValidateNoContent(responseHeaders, responseContentLength);
    }

    /// <summary>
    /// Returns true when the response status can use the Capsule Protocol.
    /// </summary>
    public static bool IsAllowedCapsuleProtocolStatus(int statusCode)
    {
        return statusCode == SwitchingProtocolsStatusCode
            || (statusCode is >= MinimumSuccessfulStatusCode and <= MaximumSuccessfulStatusCode
                && statusCode is not (NoContentStatusCode or ResetContentStatusCode or PartialContentStatusCode));
    }

    /// <summary>
    /// Returns true when an intermediary can use the header to process an unknown upgrade token.
    /// </summary>
    public static bool CanProcessUnknownUpgradeToken(IReadOnlyList<QPackFieldLine> headers)
    {
        return IsCapsuleProtocolInUse(headers);
    }

    /// <summary>
    /// Returns true when endpoints should send Capsule-Protocol for a Capsule Protocol stream.
    /// </summary>
    public static bool ShouldSendCapsuleProtocolHeader(bool usingCapsuleProtocol)
    {
        return usingCapsuleProtocol;
    }

    /// <summary>
    /// Validates a Capsule Type registry entry.
    /// </summary>
    public static void ValidateCapsuleTypeRegistration(string capsuleType, ulong value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(capsuleType);
        if (IsReservedCapsuleType(value))
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Reserved Capsule Type values must not be assigned or listed as assigned values.");
        }
    }

    /// <summary>
    /// Returns true for Capsule Type values of the form 0x29 * N + 0x17.
    /// </summary>
    public static bool IsReservedCapsuleType(ulong value)
    {
        return value >= ReservedCapsuleTypeOffset
            && ((value - ReservedCapsuleTypeOffset) % ReservedCapsuleTypeMultiplier) == 0;
    }

    /// <summary>
    /// Returns true when IANA can assign the Capsule Type value.
    /// </summary>
    public static bool CanIanaAssignCapsuleType(ulong value)
    {
        return !IsReservedCapsuleType(value);
    }

    private static void ValidateNoContent(IReadOnlyList<QPackFieldLine> headers, ulong contentLength)
    {
        if (contentLength != 0)
        {
            throw Malformed("Capsule Protocol messages must not carry HTTP content.");
        }

        for (int index = 0; index < headers.Count; index++)
        {
            string name = headers[index].Name;
            if (StringComparer.OrdinalIgnoreCase.Equals(name, "content-length")
                || StringComparer.OrdinalIgnoreCase.Equals(name, "content-type")
                || StringComparer.OrdinalIgnoreCase.Equals(name, "transfer-encoding"))
            {
                throw Malformed("Capsule Protocol messages must not include HTTP content header fields.");
            }
        }
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
