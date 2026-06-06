// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The path-validation challenge is a fixed 8-byte opaque token, so the frame keeps the
// payload as a borrowed span to avoid copying during probes.
// SEE: QuicConnectionRuntime
/// <summary>
/// A parsed or constructed PATH_CHALLENGE frame.
/// </summary>
internal readonly ref struct QuicPathChallengeFrame
{
    private readonly ReadOnlySpan<byte> data;

    /// <summary>
    /// Initializes a PATH_CHALLENGE frame view.
    /// </summary>
    internal QuicPathChallengeFrame(ReadOnlySpan<byte> data)
    {
        this.data = data;
    }

    /// <summary>
    /// Gets the 8-byte challenge payload.
    /// </summary>
    internal ReadOnlySpan<byte> Data => data;
}
