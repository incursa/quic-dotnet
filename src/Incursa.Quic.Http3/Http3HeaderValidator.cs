using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Validates HTTP/3 header and trailer field sections according to RFC 9114.
/// </summary>
public static class Http3HeaderValidator
{
    private const int MinimumStatusCode = 100;
    private const int MaximumStatusCode = 999;
    private static readonly string[] RequestPseudoHeaders = [":method", ":scheme", ":authority", ":path"];
    private static readonly string[] ResponsePseudoHeaders = [":status"];
    private static readonly string[] ProhibitedFields =
    [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ];

    /// <summary>
    /// Validates a request header section.
    /// </summary>
    public static Http3HeaderValidationResult ValidateRequestHeaders(
        IReadOnlyList<QPackFieldLine> headers,
        ulong receivedDataLength = 0,
        bool validateContentLength = true)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ValidateCommonFields(headers, Http3MessageType.Request, trailers: false);

        string? method = null;
        string? scheme = null;
        string? authority = null;
        string? path = null;
        string? host = null;
        List<ulong> contentLengths = [];

        foreach (QPackFieldLine header in headers)
        {
            switch (header.Name)
            {
                case ":method":
                    method = SetOnce(method, header.Name, header.Value);
                    break;
                case ":scheme":
                    scheme = SetOnce(scheme, header.Name, header.Value);
                    break;
                case ":authority":
                    authority = SetOnce(authority, header.Name, header.Value);
                    break;
                case ":path":
                    path = SetOnce(path, header.Name, header.Value);
                    break;
                case "host":
                    host = SetOnce(host, header.Name, header.Value);
                    break;
                case "content-length":
                    contentLengths.Add(ParseContentLength(header.Value));
                    break;
                case "te" when header.Value != "trailers":
                    throw MessageError("HTTP/3 request TE field values are limited to 'trailers'.");
            }
        }

        if (string.IsNullOrEmpty(method))
        {
            throw MessageError("HTTP/3 requests require exactly one :method pseudo-header.");
        }

        bool isConnect = method == "CONNECT";
        if (!isConnect && string.IsNullOrEmpty(scheme))
        {
            throw MessageError("HTTP/3 requests require exactly one :scheme pseudo-header.");
        }

        if (!isConnect && string.IsNullOrEmpty(path))
        {
            throw MessageError("HTTP/3 requests require exactly one :path pseudo-header.");
        }

        if (isConnect)
        {
            if (scheme is not null || path is not null || string.IsNullOrEmpty(authority))
            {
                throw MessageError("HTTP/3 CONNECT requests require :authority and must omit :scheme and :path.");
            }
        }
        else if (scheme is "http" or "https")
        {
            if (string.IsNullOrEmpty(authority) && string.IsNullOrEmpty(host))
            {
                throw MessageError("HTTP/3 http and https requests require :authority or Host.");
            }

            if (authority is not null && authority.Length == 0)
            {
                throw MessageError("HTTP/3 :authority must not be empty when present.");
            }

            if (host is not null && host.Length == 0)
            {
                throw MessageError("HTTP/3 Host must not be empty when present.");
            }

            if (authority is not null && host is not null && authority != host)
            {
                throw MessageError("HTTP/3 :authority and Host values must match when both are present.");
            }

            if (path is not null && path.Length == 0)
            {
                throw MessageError("HTTP/3 http and https requests require a non-empty :path.");
            }
        }

        if (validateContentLength)
        {
            ValidateContentLength(contentLengths, receivedDataLength);
        }

        return new Http3HeaderValidationResult(method, scheme, authority ?? host, path, statusCode: null);
    }

    /// <summary>
    /// Validates a response header section.
    /// </summary>
    public static Http3HeaderValidationResult ValidateResponseHeaders(
        IReadOnlyList<QPackFieldLine> headers,
        ulong receivedDataLength = 0,
        bool validateContentLength = true)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ValidateCommonFields(headers, Http3MessageType.Response, trailers: false);

        int? statusCode = null;
        List<ulong> contentLengths = [];
        foreach (QPackFieldLine header in headers)
        {
            switch (header.Name)
            {
                case ":status":
                    if (statusCode.HasValue)
                    {
                        throw MessageError("HTTP/3 responses require exactly one :status pseudo-header.");
                    }

                    statusCode = ParseStatus(header.Value);
                    break;
                case "content-length":
                    contentLengths.Add(ParseContentLength(header.Value));
                    break;
                case "te":
                    throw MessageError("HTTP/3 responses must not contain TE.");
            }
        }

        if (!statusCode.HasValue)
        {
            throw MessageError("HTTP/3 responses require exactly one :status pseudo-header.");
        }

        if (validateContentLength)
        {
            ValidateContentLength(contentLengths, receivedDataLength);
        }

        return new Http3HeaderValidationResult(null, null, null, null, statusCode);
    }

    /// <summary>
    /// Validates an HTTP/3 trailer section.
    /// </summary>
    public static void ValidateTrailers(IReadOnlyList<QPackFieldLine> trailers, Http3MessageType messageType)
    {
        ArgumentNullException.ThrowIfNull(trailers);
        ValidateCommonFields(trailers, messageType, trailers: true);
    }

    private static void ValidateCommonFields(
        IReadOnlyList<QPackFieldLine> fields,
        Http3MessageType messageType,
        bool trailers)
    {
        bool regularFieldSeen = false;
        foreach (QPackFieldLine field in fields)
        {
            if (string.IsNullOrEmpty(field.Name))
            {
                throw MessageError("HTTP/3 field names must not be empty.");
            }

            if (ContainsUppercaseAscii(field.Name))
            {
                throw MessageError("HTTP/3 field names must be lowercase.");
            }

            bool pseudoHeader = field.Name[0] == ':';
            if (pseudoHeader)
            {
                if (trailers)
                {
                    throw MessageError("HTTP/3 trailers must not contain pseudo-headers.");
                }

                if (regularFieldSeen)
                {
                    throw MessageError("HTTP/3 pseudo-headers must precede regular fields.");
                }

                ValidatePseudoHeaderName(field.Name, messageType);
                continue;
            }

            regularFieldSeen = true;
            ValidateRegularFieldName(field.Name);
        }
    }

    private static void ValidatePseudoHeaderName(string name, Http3MessageType messageType)
    {
        string[] allowed = messageType == Http3MessageType.Request ? RequestPseudoHeaders : ResponsePseudoHeaders;
        foreach (string candidate in allowed)
        {
            if (name == candidate)
            {
                return;
            }
        }

        throw MessageError("HTTP/3 field section contains an undefined or invalid pseudo-header.");
    }

    private static void ValidateRegularFieldName(string name)
    {
        foreach (char character in name)
        {
            if (!IsTokenCharacter(character))
            {
                throw MessageError("HTTP/3 field name contains an invalid character.");
            }
        }

        foreach (string prohibited in ProhibitedFields)
        {
            if (name == prohibited)
            {
                throw MessageError("HTTP/3 field section contains a prohibited connection-specific field.");
            }
        }
    }

    private static bool ContainsUppercaseAscii(string value)
    {
        foreach (char character in value)
        {
            if (character is >= 'A' and <= 'Z')
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsTokenCharacter(char character)
    {
        return character is >= 'a' and <= 'z'
            || character is >= '0' and <= '9'
            || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';
    }

    private static string SetOnce(string? current, string name, string value)
    {
        if (current is not null)
        {
            throw MessageError($"HTTP/3 field section contains duplicate {name} pseudo-header.");
        }

        return value;
    }

    private static int ParseStatus(string value)
    {
        if (value.Length != 3 || !int.TryParse(value, out int statusCode) || statusCode < MinimumStatusCode || statusCode > MaximumStatusCode)
        {
            throw MessageError("HTTP/3 :status must be a three-digit status code.");
        }

        return statusCode;
    }

    private static ulong ParseContentLength(string value)
    {
        if (value.Length == 0 || !ulong.TryParse(value, out ulong length))
        {
            throw MessageError("HTTP/3 Content-Length is invalid.");
        }

        return length;
    }

    private static void ValidateContentLength(IReadOnlyList<ulong> contentLengths, ulong receivedDataLength)
    {
        if (contentLengths.Count == 0)
        {
            return;
        }

        ulong expected = contentLengths[0];
        foreach (ulong contentLength in contentLengths)
        {
            if (contentLength != expected)
            {
                throw MessageError("HTTP/3 duplicate Content-Length values must match.");
            }
        }

        if (expected != receivedDataLength)
        {
            throw MessageError("HTTP/3 Content-Length does not match received DATA length.");
        }
    }

    private static Http3Exception MessageError(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
