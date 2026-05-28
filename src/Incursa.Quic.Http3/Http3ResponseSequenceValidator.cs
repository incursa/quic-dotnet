// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Validates the sequence of response HEADERS and DATA frames on a request stream.
/// </summary>
public sealed class Http3ResponseSequenceValidator
{
    private const int MinimumInformationalStatusCode = 100;
    private const int MaximumInformationalStatusCode = 199;

    private bool finalResponseSeen;
    private bool trailersSeen;
    private ulong finalResponseDataLength;
    private QPackFieldLine[]? finalResponseHeaders;

    /// <summary>
    /// Gets the final response headers after they have been received.
    /// </summary>
    public IReadOnlyList<QPackFieldLine>? FinalResponseHeaders => finalResponseHeaders;

    /// <summary>
    /// Gets the validated final response status code after final response headers have been received.
    /// </summary>
    public int? FinalStatusCode { get; private set; }

    /// <summary>
    /// Gets whether the final response headers have been received.
    /// </summary>
    public bool FinalResponseSeen => finalResponseSeen;

    /// <summary>
    /// Applies a response HEADERS frame.
    /// </summary>
    public bool ReceiveHeaders(IReadOnlyList<QPackFieldLine> headers, bool trailersSupported = false)
    {
        ArgumentNullException.ThrowIfNull(headers);
        if (trailersSeen)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "HTTP/3 HEADERS cannot follow trailers.");
        }

        if (!finalResponseSeen)
        {
            Http3HeaderValidationResult result = Http3HeaderValidator.ValidateResponseHeaders(
                headers,
                validateContentLength: false);
            int statusCode = result.StatusCode!.Value;
            if (statusCode is >= MinimumInformationalStatusCode and <= MaximumInformationalStatusCode)
            {
                return false;
            }

            finalResponseSeen = true;
            FinalStatusCode = statusCode;
            finalResponseHeaders = headers.ToArray();
            return true;
        }

        if (!trailersSupported)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "HTTP/3 response trailers are not supported.");
        }

        Http3HeaderValidator.ValidateTrailers(headers, Http3MessageType.Response);
        trailersSeen = true;
        return false;
    }

    /// <summary>
    /// Applies received DATA bytes to the current response sequence.
    /// </summary>
    public void ReceiveData(ulong dataLength)
    {
        if (!finalResponseSeen || trailersSeen)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "HTTP/3 DATA appeared outside the final response content section.");
        }

        finalResponseDataLength = checked(finalResponseDataLength + dataLength);
    }

    /// <summary>
    /// Validates stream completion.
    /// </summary>
    public void Complete()
    {
        if (!finalResponseSeen || finalResponseHeaders is null)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "HTTP/3 response stream ended without a final response.");
        }

        Http3HeaderValidator.ValidateResponseHeaders(finalResponseHeaders, finalResponseDataLength);
    }
}
