// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents a decoded HTTP/3 request that contains only HEADERS and no DATA payload.
/// </summary>
public readonly struct Http3HeadersOnlyRequest
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3HeadersOnlyRequest" /> struct.
    /// </summary>
    public Http3HeadersOnlyRequest(
        string method,
        string scheme,
        string authority,
        string path,
        string? protocol,
        IReadOnlyList<QPackFieldLine> headers)
    {
        Method = method ?? throw new ArgumentNullException(nameof(method));
        Scheme = scheme ?? throw new ArgumentNullException(nameof(scheme));
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        Path = path ?? throw new ArgumentNullException(nameof(path));
        Protocol = protocol;
        Headers = headers ?? throw new ArgumentNullException(nameof(headers));
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
    /// Gets the decoded RFC 9220 Extended CONNECT :protocol pseudo-field, when present.
    /// </summary>
    public string? Protocol { get; }

    /// <summary>
    /// Gets all decoded request field lines in wire order.
    /// </summary>
    public IReadOnlyList<QPackFieldLine> Headers { get; }
}
