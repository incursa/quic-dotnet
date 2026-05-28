// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 frame whose payload is a single variable-length integer identifier.
/// </summary>
public abstract class Http3IdFrame : Http3Frame
{
    private protected Http3IdFrame(ulong type, ulong identifier, byte[] payload)
        : base(type, payload)
    {
        Identifier = identifier;
    }

    /// <summary>
    /// Gets the frame identifier value.
    /// </summary>
    public ulong Identifier { get; }
}
