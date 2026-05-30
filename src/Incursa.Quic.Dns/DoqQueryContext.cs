// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Describes a DNS over QUIC query delivered to a server handler.
/// </summary>
public sealed class DoqQueryContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DoqQueryContext"/> class.
    /// </summary>
    public DoqQueryContext(long streamId, ReadOnlyMemory<byte> query)
    {
        StreamId = streamId;
        Query = query;
    }

    /// <summary>
    /// Gets the QUIC stream ID carrying the DoQ transaction.
    /// </summary>
    public long StreamId { get; }

    /// <summary>
    /// Gets the DNS query payload without the DoQ length prefix.
    /// </summary>
    public ReadOnlyMemory<byte> Query { get; }

    /// <summary>
    /// Gets or sets a value indicating whether the query arrived via QUIC 0-RTT.
    /// Defaults to <c>false</c>. The transport layer does not currently expose
    /// 0-RTT state; this property is a placeholder for future integration.
    /// </summary>
    public bool IsZeroRtt { get; set; }
}
