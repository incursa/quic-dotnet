// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes an RFC 9297 intermediary forwarding decision for HTTP Datagrams.
/// </summary>
public enum Http3DatagramIntermediaryAction
{
    /// <summary>
    /// Forward the HTTP Datagram in a QUIC DATAGRAM frame.
    /// </summary>
    ForwardAsDatagramFrame,

    /// <summary>
    /// Re-encode the HTTP Datagram as a DATAGRAM Capsule.
    /// </summary>
    ReencodeAsDatagramCapsule,

    /// <summary>
    /// Re-encode the DATAGRAM Capsule as a QUIC DATAGRAM frame.
    /// </summary>
    ReencodeAsDatagramFrame,

    /// <summary>
    /// Drop the HTTP Datagram without buffering it.
    /// </summary>
    Drop,

    /// <summary>
    /// Do not re-encode because Capsule Protocol use has not been identified.
    /// </summary>
    RequireCapsuleProtocolIdentification,
}
