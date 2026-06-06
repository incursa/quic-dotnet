// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The token is opaque server-issued retry state, so it is carried as a borrowed span
// instead of being copied into a heap-owned buffer during parse.
// SEE: QuicListenerHost
/// <summary>
/// A parsed or constructed NEW_TOKEN frame.
/// </summary>
internal readonly ref struct QuicNewTokenFrame
{
    private readonly ReadOnlySpan<byte> token;

    /// <summary>
    /// Initializes a NEW_TOKEN frame view.
    /// </summary>
    internal QuicNewTokenFrame(ReadOnlySpan<byte> token)
    {
        this.token = token;
    }

    /// <summary>
    /// Gets the token bytes.
    /// </summary>
    internal ReadOnlySpan<byte> Token => token;
}
