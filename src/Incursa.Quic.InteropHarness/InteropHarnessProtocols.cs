// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Security;

namespace Incursa.Quic.InteropHarness;

internal static class InteropHarnessProtocols
{
    internal static readonly SslApplicationProtocol QuicInterop = new("hq-interop");
}
