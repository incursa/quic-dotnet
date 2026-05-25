namespace Incursa.Quic.Http3;

/// <summary>
/// Contains validated HTTP/3 control data.
/// </summary>
public sealed class Http3HeaderValidationResult
{
    internal Http3HeaderValidationResult(
        string? method,
        string? scheme,
        string? authority,
        string? path,
        int? statusCode)
    {
        Method = method;
        Scheme = scheme;
        Authority = authority;
        Path = path;
        StatusCode = statusCode;
    }

    /// <summary>
    /// Gets the validated :method value for requests.
    /// </summary>
    public string? Method { get; }

    /// <summary>
    /// Gets the validated :scheme value for requests.
    /// </summary>
    public string? Scheme { get; }

    /// <summary>
    /// Gets the validated :authority value for requests.
    /// </summary>
    public string? Authority { get; }

    /// <summary>
    /// Gets the validated :path value for requests.
    /// </summary>
    public string? Path { get; }

    /// <summary>
    /// Gets the validated :status value for responses.
    /// </summary>
    public int? StatusCode { get; }
}
