// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes what RFC 9484 means by a stream reference for a selected HTTP version.
/// </summary>
public enum Http3ConnectIpStreamReferenceScope
{
    /// <summary>
    /// Stream references identify an individual multiplexed request stream.
    /// </summary>
    RequestStream,

    /// <summary>
    /// Stream references identify the entire connection for HTTP versions without stream multiplexing.
    /// </summary>
    EntireConnection,
}
