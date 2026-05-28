using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Validates the sequence of request HEADERS and DATA frames on a request stream.
/// </summary>
public sealed class Http3RequestMessageValidator
{
    private bool headersSeen;
    private bool trailersSeen;
    private ulong dataLength;
    private IReadOnlyList<QPackFieldLine>? headers;

    /// <summary>
    /// Gets the validated request headers after header validation completes.
    /// </summary>
    public IReadOnlyList<QPackFieldLine>? Headers => headers;

    /// <summary>
    /// Applies a request HEADERS frame.
    /// </summary>
    public void ReceiveHeaders(IReadOnlyList<QPackFieldLine> fieldSection, bool trailersSupported = false)
    {
        ArgumentNullException.ThrowIfNull(fieldSection);
        ReceiveHeadersCore(fieldSection, ownedFieldSection: null, trailersSupported);
    }

    internal void ReceiveOwnedHeaders(QPackFieldLine[] fieldSection, bool trailersSupported = false)
    {
        ArgumentNullException.ThrowIfNull(fieldSection);
        ReceiveHeadersCore(fieldSection, fieldSection, trailersSupported);
    }

    internal void ReceiveOwnedHeaders(IReadOnlyList<QPackFieldLine> fieldSection, bool trailersSupported = false)
    {
        ArgumentNullException.ThrowIfNull(fieldSection);
        ReceiveHeadersCore(fieldSection, fieldSection, trailersSupported);
    }

    private void ReceiveHeadersCore(
        IReadOnlyList<QPackFieldLine> fieldSection,
        IReadOnlyList<QPackFieldLine>? ownedFieldSection,
        bool trailersSupported)
    {
        if (!headersSeen)
        {
            Http3HeaderValidator.ValidateRequestHeaders(fieldSection, validateContentLength: false);
            headers = ownedFieldSection ?? fieldSection.ToArray();
            headersSeen = true;
            return;
        }

        if (!trailersSupported)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "HTTP/3 request trailers are not supported.");
        }

        Http3HeaderValidator.ValidateTrailers(fieldSection, Http3MessageType.Request);
        trailersSeen = true;
    }

    /// <summary>
    /// Applies received DATA bytes to the current request sequence.
    /// </summary>
    public void ReceiveData(ulong length)
    {
        if (!headersSeen || trailersSeen)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "HTTP/3 DATA appeared outside the request content section.");
        }

        dataLength = checked(dataLength + length);
    }

    /// <summary>
    /// Validates stream completion.
    /// </summary>
    public void Complete()
    {
        if (!headersSeen || headers is null)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "HTTP/3 request stream ended without request headers.");
        }

        Http3HeaderValidator.ValidateRequestHeaders(headers, dataLength);
    }
}
