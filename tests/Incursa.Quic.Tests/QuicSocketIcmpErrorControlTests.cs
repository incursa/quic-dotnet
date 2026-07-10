// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Sockets;

namespace Incursa.Quic.Tests;

public sealed class QuicSocketIcmpErrorControlTests
{
    [Fact]
    public void TryDisablePortUnreachableReporting_MatchesPlatformCapability()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        bool configured = QuicSocketIcmpErrorControl.TryDisablePortUnreachableReporting(socket);

        Assert.Equal(OperatingSystem.IsWindows(), configured);
    }
}
