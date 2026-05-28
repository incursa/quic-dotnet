// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed PATH_RESPONSE frame.
/// </summary>
internal readonly ref struct QuicPathResponseFrame
{
    private readonly ReadOnlySpan<byte> data;

    /// <summary>
    /// Initializes a PATH_RESPONSE frame view.
    /// </summary>
    internal QuicPathResponseFrame(ReadOnlySpan<byte> data)
    {
        this.data = data;
    }

    /// <summary>
    /// Gets the 8-byte response payload.
    /// </summary>
    internal ReadOnlySpan<byte> Data => data;
}

