// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Specifies which side of a stream should be aborted.
/// </summary>
[Flags]
public enum QuicAbortDirection
{
    /// <summary>
    /// Abort the read side of the stream.
    /// </summary>
    Read = 1,

    /// <summary>
    /// Abort the write side of the stream.
    /// </summary>
    Write = 2,

    /// <summary>
    /// Abort both sides of the stream.
    /// </summary>
    Both = Read | Write,
}

