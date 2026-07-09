// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Handles decoded headers-only requests for the minimal HTTP/3 server without requiring a full request object.
/// </summary>
public interface IHttp3HeadersOnlyRequestHandler
{
    /// <summary>
    /// Handles one decoded HTTP/3 request that contains no DATA payload.
    /// </summary>
    ValueTask<Http3ServerResponse> HandleHeadersOnlyAsync(
        Http3HeadersOnlyRequest request,
        CancellationToken cancellationToken = default);
}
