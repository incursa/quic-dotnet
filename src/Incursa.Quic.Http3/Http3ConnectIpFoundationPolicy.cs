// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 CONNECT-IP foundation policy helpers.
/// </summary>
public static class Http3ConnectIpFoundationPolicy
{
    /// <summary>
    /// Gets the RFC 9484 Extended CONNECT protocol token.
    /// </summary>
    public const string ProtocolToken = "connect-ip";

    /// <summary>
    /// Indicates that CONNECT-IP payload mechanisms do not convey fields of the IP header.
    /// </summary>
    public const bool ConveysIpHeaderFields = false;

    /// <summary>
    /// Indicates that CONNECT-IP mechanisms do not tunnel protocols other than IP.
    /// </summary>
    public const bool TunnelsOtherIpProtocols = false;

    /// <summary>
    /// Validates whether a CONNECT-IP payload description stays within the RFC 9484 mechanism scope.
    /// </summary>
    public static void ValidatePayloadMechanismScope(bool conveysIpHeaderFields, bool tunnelsOtherIpProtocols)
    {
        if (conveysIpHeaderFields)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "CONNECT-IP mechanisms must not convey IP header fields.");
        }

        if (tunnelsOtherIpProtocols)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "CONNECT-IP mechanisms must not tunnel protocols other than IP.");
        }
    }

    /// <summary>
    /// Formats a value using QUIC variable-length integer encoding.
    /// </summary>
    public static byte[] EncodeVariableLengthInteger(ulong value)
    {
        byte[] buffer = new byte[Http3VariableLengthInteger.MaxEncodedLength];
        if (!Http3VariableLengthInteger.TryFormat(value, buffer, out int bytesWritten))
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        return buffer[..bytesWritten];
    }

    /// <summary>
    /// Parses a value using QUIC variable-length integer encoding.
    /// </summary>
    public static bool TryDecodeVariableLengthInteger(ReadOnlySpan<byte> encoded, out ulong value, out int bytesConsumed)
    {
        return Http3VariableLengthInteger.TryParse(encoded, out value, out bytesConsumed);
    }

    /// <summary>
    /// Returns the RFC 9484 stream-reference scope for the HTTP version in use.
    /// </summary>
    public static Http3ConnectIpStreamReferenceScope GetStreamReferenceScope(bool httpVersionSupportsMultiplexingStreams)
    {
        return httpVersionSupportsMultiplexingStreams
            ? Http3ConnectIpStreamReferenceScope.RequestStream
            : Http3ConnectIpStreamReferenceScope.EntireConnection;
    }
}
