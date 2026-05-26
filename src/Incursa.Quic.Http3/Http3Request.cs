using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents one decoded HTTP/3 request.
/// </summary>
public sealed class Http3Request
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3Request" /> class.
    /// </summary>
    public Http3Request(
        string method,
        string scheme,
        string authority,
        string path,
        IReadOnlyList<QPackFieldLine> headers)
        : this(method, scheme, authority, path, headers, ReadOnlyMemory<byte>.Empty)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3Request" /> class.
    /// </summary>
    public Http3Request(
        string method,
        string scheme,
        string authority,
        string path,
        IReadOnlyList<QPackFieldLine> headers,
        ReadOnlyMemory<byte> body)
    {
        Method = method ?? throw new ArgumentNullException(nameof(method));
        Scheme = scheme ?? throw new ArgumentNullException(nameof(scheme));
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        Path = path ?? throw new ArgumentNullException(nameof(path));
        Headers = headers ?? throw new ArgumentNullException(nameof(headers));
        Body = body.ToArray();
    }

    /// <summary>
    /// Gets the decoded :method pseudo-field.
    /// </summary>
    public string Method { get; }

    /// <summary>
    /// Gets the decoded :scheme pseudo-field.
    /// </summary>
    public string Scheme { get; }

    /// <summary>
    /// Gets the decoded :authority pseudo-field.
    /// </summary>
    public string Authority { get; }

    /// <summary>
    /// Gets the decoded :path pseudo-field.
    /// </summary>
    public string Path { get; }

    /// <summary>
    /// Gets all decoded request field lines in wire order.
    /// </summary>
    public IReadOnlyList<QPackFieldLine> Headers { get; }

    /// <summary>
    /// Gets the concatenated request DATA payload.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; }
}
