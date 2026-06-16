// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// IKEv2 Configuration payload types relevant to RFC 9464 encrypted DNS provisioning attributes.
/// </summary>
public enum EncryptedDnsProvisioningPayloadType
{
    /// <summary>
    /// CFG_REQUEST.
    /// </summary>
    Request,

    /// <summary>
    /// CFG_REPLY.
    /// </summary>
    Reply,

    /// <summary>
    /// CFG_SET.
    /// </summary>
    Set,

    /// <summary>
    /// CFG_ACK.
    /// </summary>
    Ack,
}
