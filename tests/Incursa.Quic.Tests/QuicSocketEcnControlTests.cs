// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

using System.Net.Sockets;

public sealed class QuicSocketEcnControlTests
{
    [Fact]
    [Trait("Category", "Guardrail")]
    public void ReceiveEcnMetadataCapability_DocumentsManagedReceivePathBlocker()
    {
        QuicReceiveEcnMetadataCapability capability = QuicSocketEcnControl.GetReceiveEcnMetadataCapability();

        Assert.False(capability.IsSupported);
        Assert.Contains("Socket.ReceiveMessageFromAsync", capability.Reason, StringComparison.Ordinal);
        Assert.Contains("SocketReceiveMessageFromResult", capability.Reason, StringComparison.Ordinal);
        Assert.Contains("IP_TOS", capability.Reason, StringComparison.Ordinal);
        Assert.Contains("IPV6_TCLASS", capability.Reason, StringComparison.Ordinal);
        Assert.Contains("native or control-message receive path", capability.Reason, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Guardrail")]
    public void TryGetReceivedEcnCounts_ReturnsFalseForManagedReceiveResult()
    {
        SocketReceiveMessageFromResult receiveResult = new()
        {
            ReceivedBytes = 1,
        };

        Assert.False(QuicSocketEcnControl.TryGetReceivedEcnCounts(receiveResult, out QuicEcnCounts ecnCounts));
        Assert.Equal(default, ecnCounts);
    }
}
