// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents a decoded HTTP/3 request whose DATA payload can be consumed incrementally.
/// </summary>
public sealed class Http3StreamingRequest
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3StreamingRequest" /> class.
    /// </summary>
    public Http3StreamingRequest(
        string method,
        string scheme,
        string authority,
        string path,
        string? protocol,
        IReadOnlyList<QPackFieldLine> headers,
        IAsyncEnumerable<ReadOnlyMemory<byte>> body)
    {
        Method = method ?? throw new ArgumentNullException(nameof(method));
        Scheme = scheme ?? throw new ArgumentNullException(nameof(scheme));
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        Path = path ?? throw new ArgumentNullException(nameof(path));
        Protocol = protocol;
        Headers = headers ?? throw new ArgumentNullException(nameof(headers));
        Body = body ?? throw new ArgumentNullException(nameof(body));
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

    /// <summary>
    /// Gets the single-use sequence of owned request DATA payload chunks.
    /// </summary>
    /// <remarks>
    /// Chunks remain valid after the next move. The sequence is valid only
    /// while the server is handling this request and may be enumerated once.
    /// </remarks>
    public IAsyncEnumerable<ReadOnlyMemory<byte>> Body { get; }
}
