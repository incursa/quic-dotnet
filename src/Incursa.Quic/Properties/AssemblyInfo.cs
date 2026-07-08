// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Runtime.CompilerServices;

// CONTEXT: The visibility list stays centralized here so test, benchmark, fuzz, and sibling
// project access remains explicit instead of being scattered through the source tree.
[assembly: InternalsVisibleTo("Incursa.Quic.Tests")]
[assembly: InternalsVisibleTo("Incursa.Quic.Dns")]
[assembly: InternalsVisibleTo("Incursa.Quic.Benchmarks")]
[assembly: InternalsVisibleTo("Incursa.Quic.Http3")]
[assembly: InternalsVisibleTo("Incursa.Quic.InteropHarness")]
[assembly: InternalsVisibleTo("Incursa.Quic.Qlog")]
[assembly: InternalsVisibleTo("Incursa.Quic.Fuzz")]
[assembly: InternalsVisibleTo("IncursaRawQuicServer")]
