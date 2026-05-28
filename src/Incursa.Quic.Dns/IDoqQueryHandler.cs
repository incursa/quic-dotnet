// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Handles DNS over QUIC queries delivered by <see cref="DoqServer"/>.
/// </summary>
public interface IDoqQueryHandler
{
    /// <summary>
    /// Handles one DNS query and returns the response payload to write on the same QUIC stream.
    /// </summary>
    ValueTask<DoqQueryResult> HandleAsync(DoqQueryContext context, CancellationToken cancellationToken = default);
}
