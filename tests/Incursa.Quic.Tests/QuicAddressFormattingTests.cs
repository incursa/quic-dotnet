// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class QuicAddressFormattingTests
{
    [Fact]
    public void FormatIPAddress_UsesCanonicalTextForIpv4AndIpv6()
    {
        Assert.Equal("127.0.0.1", QuicAddressFormatting.Format(IPAddress.Loopback));
        Assert.Equal("2001:db8::1", QuicAddressFormatting.Format(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void FormatAddressBytes_UsesCanonicalTextForPreferredAddressBytes()
    {
        Assert.Equal("192.0.2.10", QuicAddressFormatting.Format([192, 0, 2, 10]));
        Assert.Equal("2001:db8::10", QuicAddressFormatting.Format([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]));
    }
}
