// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Handles selected HTTP/3 requests before their complete DATA payload has been buffered.
/// </summary>
public interface IHttp3StreamingRequestHandler
{
    /// <summary>
    /// Determines whether a request should use the streaming handler path.
    /// </summary>
    /// <remarks>
    /// This method must not enumerate <see cref="Http3StreamingRequest.Body" />.
    /// Returning <see langword="false" /> preserves the normal buffered
    /// <see cref="IHttp3RequestHandler" /> path.
    /// </remarks>
    bool CanHandleStreaming(Http3StreamingRequest request);

    /// <summary>
    /// Handles a selected request while its DATA payload remains available as an asynchronous stream.
    /// </summary>
    ValueTask<Http3ServerResponse> HandleStreamingAsync(
        Http3StreamingRequest request,
        CancellationToken cancellationToken = default);
}
