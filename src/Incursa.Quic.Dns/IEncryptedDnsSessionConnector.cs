// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Adapter contract for establishing a planned encrypted DNS session.
/// </summary>
public interface IEncryptedDnsSessionConnector
{
    /// <summary>
    /// Attempts to establish the supplied encrypted DNS session.
    /// </summary>
    EncryptedDnsAdapterResult Connect(EncryptedDnsSessionAttempt attempt);
}
