// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Adapter contract for carrying RFC 9464 Configuration Payloads over a future IKEv2/IPsec transport.
/// </summary>
public interface IEncryptedDnsProvisioningTransport
{
    /// <summary>
    /// Exchanges a CFG_REQUEST payload and returns the received CFG_REPLY payload.
    /// </summary>
    EncryptedDnsProvisioningConfigurationPayload Exchange(EncryptedDnsProvisioningConfigurationPayload requestPayload);
}
