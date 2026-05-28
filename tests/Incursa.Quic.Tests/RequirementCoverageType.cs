// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <summary>
/// Describes the kind of evidence a test provides.
/// </summary>
public enum RequirementCoverageType
{
    Positive,
    Negative,
    Edge,
    Fuzz,
    Benchmark
}
