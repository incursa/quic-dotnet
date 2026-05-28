// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an unknown or reserved HTTP/3 frame.
/// </summary>
public sealed class Http3UnknownFrame : Http3Frame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3UnknownFrame" /> class.
    /// </summary>
    public Http3UnknownFrame(ulong type, byte[] payload)
        : base(type, payload)
    {
    }
}
