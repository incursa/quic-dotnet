// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Handles decoded requests for the minimal HTTP/3 server.
/// </summary>
public interface IHttp3RequestHandler
{
    /// <summary>
    /// Handles one decoded HTTP/3 request.
    /// </summary>
    ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default);
}
