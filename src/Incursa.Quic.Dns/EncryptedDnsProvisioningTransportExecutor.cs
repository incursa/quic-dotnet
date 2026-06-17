// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Executes local RFC 9464 payload exchange through an explicit transport adapter.
/// </summary>
public static class EncryptedDnsProvisioningTransportExecutor
{
    /// <summary>
    /// Exchanges a CFG_REQUEST through the supplied transport adapter.
    /// </summary>
    public static EncryptedDnsProvisioningConfigurationPayload Exchange(
        EncryptedDnsProvisioningConfigurationPayload requestPayload,
        IEncryptedDnsProvisioningTransport transport)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentNullException.ThrowIfNull(transport);
        if (requestPayload.PayloadType != EncryptedDnsProvisioningPayloadType.Request)
        {
            throw new ArgumentException("Only CFG_REQUEST payloads can be exchanged through provisioning transport.", nameof(requestPayload));
        }

        EncryptedDnsProvisioningConfigurationPayload responsePayload = transport.Exchange(requestPayload);
        if (responsePayload.PayloadType != EncryptedDnsProvisioningPayloadType.Reply)
        {
            throw new InvalidOperationException("Encrypted DNS provisioning transport must return a CFG_REPLY payload.");
        }

        return responsePayload;
    }
}
