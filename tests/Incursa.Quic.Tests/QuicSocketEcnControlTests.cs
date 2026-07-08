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

    [Fact]
    [Trait("Category", "Guardrail")]
    public void SendRuntime_UsesNotEctWhenReceiveEcnMetadataIsUnavailable()
    {
        Assert.False(QuicSocketEcnControl.GetReceiveEcnMetadataCapability().IsSupported);

        QuicConnectionSendRuntime runtime = new();

        Assert.True(runtime.EcnValidationState.IsEcnEnabled);
        Assert.Equal(QuicEcnMarking.NotEct, runtime.CurrentEcnMarking);
    }

    [Fact]
    [Trait("Category", "Guardrail")]
    public void TrySetEcnMarkingIfPossible_SkipsIpv4SocketOptionWhenGloballyUnavailable()
    {
        QuicSocketEcnControl.ResetGlobalSocketOptionSupportForTest();

        try
        {
            QuicSocketEcnControl.MarkGlobalSocketOptionUnavailableForTest(ipv6: false);

            using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            Assert.False(QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, QuicEcnMarking.Ect0));
        }
        finally
        {
            QuicSocketEcnControl.ResetGlobalSocketOptionSupportForTest();
        }
    }

    [Fact]
    [Trait("Category", "Guardrail")]
    public void TrySetEcnMarkingIfPossible_TreatsFreshNotEctSocketAsAlreadyClear()
    {
        QuicSocketEcnControl.ResetGlobalSocketOptionSupportForTest();

        try
        {
            using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            Assert.True(QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, QuicEcnMarking.NotEct));
        }
        finally
        {
            QuicSocketEcnControl.ResetGlobalSocketOptionSupportForTest();
        }
    }

    [Fact]
    [Trait("Category", "Guardrail")]
    public void TrySetEcnMarkingIfPossible_SkipsIpv6AndFallbackIpOptionsWhenGloballyUnavailable()
    {
        QuicSocketEcnControl.ResetGlobalSocketOptionSupportForTest();

        try
        {
            QuicSocketEcnControl.MarkGlobalSocketOptionUnavailableForTest(ipv6: true);
            QuicSocketEcnControl.MarkGlobalSocketOptionUnavailableForTest(ipv6: false);

            using Socket socket = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);

            Assert.False(QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, QuicEcnMarking.Ect1));
        }
        finally
        {
            QuicSocketEcnControl.ResetGlobalSocketOptionSupportForTest();
        }
    }
}
