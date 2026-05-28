// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// HTTP/3 unidirectional stream type values defined by RFC 9114.
/// </summary>
public enum Http3StreamType : long
{
    /// <summary>
    /// HTTP/3 control stream.
    /// </summary>
    Control = 0x00,

    /// <summary>
    /// HTTP/3 push stream.
    /// </summary>
    Push = 0x01,

    /// <summary>
    /// QPACK encoder stream.
    /// </summary>
    QPackEncoder = 0x02,

    /// <summary>
    /// QPACK decoder stream.
    /// </summary>
    QPackDecoder = 0x03,
}
